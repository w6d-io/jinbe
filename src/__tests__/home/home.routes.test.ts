import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// GET /api/home and /api/home/:module (home-data.md §3, §11): scope from OPA, modules the caller may
// not see omitted, ?org= checked against the scope, each module degrading on its own, SWR staleness.

vi.mock('../../authz/opa.js', async () => (await import('../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../home/sources.js', async () => (await import('./world.js')).sourcesMock())
vi.mock('../../services/redis-client.service.js', async () => (await import('./world.js')).redisMock())

import { opaWorld, resetOpaWorld } from '../helpers/opa-authz-mock.js'
import { world, resetWorld, failing, hanging, redisHolder, MemoryRedis, settle, ORG_A, ORG_B } from './world.js'
import { homeRoutes } from '../../home/routes.js'
import { resetLabels } from '../../home/labels.js'
import { invalidateHome, resetHomeCacheState } from '../../home/cache.js'
import { declaredRoutes, resetDeclaredRoutes } from '../../policy/declared-routes.js'
import { homeResponseSchema, moduleEnvelopeSchema } from '../../home/types.js'

let app: FastifyInstance
beforeAll(async () => {
  resetDeclaredRoutes()
  app = Fastify()
  app.addHook('onRequest', async (request) => {
    const id = request.headers['x-test-subject'] as string | undefined
    if (id) request.userContext = { id, email: `${id}@example.com`, name: `Name ${id}`, aal: 'aal2' }
  })
  await app.register(homeRoutes, { prefix: '/api/home' })
  await app.ready()
})
afterAll(() => app.close())

const email = (id: string) => `${id}@example.com`

beforeEach(() => {
  resetWorld()
  resetOpaWorld()
  resetLabels()
  resetHomeCacheState()
  redisHolder.redis = new MemoryRedis()
  // root: super admin · admin: admin:read without apply · support · org admins · nobody
  opaWorld.permissions[email('root')] = ['*']
  opaWorld.superAdmins.add(email('root'))
  opaWorld.permissions[email('admin')] = ['admin:read', 'admin:write']
  opaWorld.permissions[email('support')] = ['users:read', 'sessions:read', 'sessions:revoke', 'users:recovery']
  opaWorld.manageable[email('orga')] = [ORG_A]
  opaWorld.manageable[email('orgab')] = [ORG_A, ORG_B]
})

const get = (url: string, subject = 'root') => app.inject({ method: 'GET', url, headers: { 'x-test-subject': subject } })
/** Two calls: the first may answer `warming` for background modules while their refresh runs. */
async function warm(url: string, subject = 'root') {
  await get(url, subject)
  await settle()
  return get(url, subject)
}

describe('GET /api/home — envelope and scope', () => {
  it('answers every module to a super admin, in the contract shape, privately cacheable', async () => {
    const res = await warm('/api/home')
    expect(res.statusCode).toBe(200)
    expect(res.headers['cache-control']).toBe('private, max-age=15')
    const body = res.json()
    expect(homeResponseSchema.safeParse(body).success).toBe(true)
    expect(Object.keys(body.modules).sort()).toEqual(['access', 'actions', 'activity', 'attention', 'changes', 'health', 'me', 'people', 'sites'])
    expect(body.scope).toEqual({ platform: true, orgs: [], roles: [], org: null })
    expect(body.window).toBe('24h')
    for (const m of Object.values(body.modules) as Array<Record<string, unknown>>) {
      expect(m).toHaveProperty('stale')
      expect(m).toHaveProperty('sources')
      expect(m).toHaveProperty('asOf')
    }
  })

  it('never lets an address out, though the stores hold them (privacy rule 1)', async () => {
    world.legacyChanges = [{ id: '1-0', ts: new Date().toISOString(), category: 'rbac', kind: 'change', verb: 'assign', target: 'user:ada@example.com', result: 'ok', who: 'bob@example.com' }]
    const res = await warm('/api/home')
    expect(res.body).not.toContain('@')
    const body = res.json()
    const payroll = body.modules.sites.data.list.find((s: { name: string }) => s.name === 'payroll')
    expect(payroll.appliedBy).toEqual({ id: 'id-ada', label: 'Ada Lovelace' })
    expect(body.modules.changes.data.items[0]).toMatchObject({ actor: { id: 'id-bob', label: 'Bob Chen', type: 'user' }, target: { type: 'user', id: null, label: 'Ada Lovelace' } })
  })

  it('401 without a caller, 503 when OPA cannot tell (never a narrowed Home)', async () => {
    expect((await app.inject({ method: 'GET', url: '/api/home' })).statusCode).toBe(401)
    opaWorld.down = true
    const res = await get('/api/home')
    expect(res.statusCode).toBe(503)
    expect(res.json().error).toBe('policy_unavailable')
    expect(res.json().modules).toBeUndefined()
  })

  it('refuses an unknown window or a malformed org', async () => {
    expect((await get('/api/home?window=30d')).statusCode).toBe(400)
    expect((await get('/api/home?org=../x')).statusCode).toBe(400)
  })

  it('is published in the route table as authenticated (its guard narrows, it does not refuse)', () => {
    const rows = declaredRoutes().filter((r) => r.path.startsWith('/api/home') && r.method === 'GET')
    expect(rows.map((r) => `${r.method} ${r.path} ${r.class}`)).toEqual(['GET /api/home authenticated', 'GET /api/home/:module authenticated'])
  })
})

describe('module visibility (§3.3) — forbidden modules are omitted', () => {
  it('support: attention, people (totals only), actions, me', async () => {
    const body = (await warm('/api/home', 'support')).json()
    expect(Object.keys(body.modules).sort()).toEqual(['actions', 'attention', 'me', 'people'])
    expect(body.modules.people.data).toEqual({ identities: 12, active: 10, inactive: 2 })
    const enabled = body.modules.actions.data.items.filter((i: { enabled: boolean }) => i.enabled).map((i: { id: string }) => i.id).sort()
    expect(enabled).toEqual(['find_user', 'revoke_sessions', 'send_recovery'])
  })

  it('a caller with no rights: their own queue, actions and me — nothing about the platform', async () => {
    world.inbox[email('nobody')] = [{ deadline: new Date(Date.now() + 86_400_000).toISOString() }]
    const body = (await get('/api/home', 'nobody')).json()
    expect(Object.keys(body.modules).sort()).toEqual(['actions', 'attention', 'me'])
    expect(body.modules.attention.data.items.map((i: { kind: string }) => i.kind)).toEqual(['recert_inbox'])
    expect(body.modules.me.data).toMatchObject({ subject: 'nobody', name: 'Name nobody', recertPending: 1, aal: 'aal2', orgs: [] })
  })

  it('an org admin sees no health strip and only the sites of their orgs', async () => {
    const body = (await warm('/api/home', 'orga')).json()
    expect(body.modules.health).toBeUndefined()
    expect(body.scope).toMatchObject({ platform: false, orgs: [ORG_A] })
    expect(body.modules.sites.data.list.map((s: { name: string }) => s.name)).toEqual(['payroll'])
    expect(body.modules.sites.data.pendingRequests).toBe(0)
    expect(body.modules.people.data).toEqual({ identities: 2, active: 1, inactive: 1, byOrg: [{ orgId: ORG_A, name: 'Acme', members: 2 }], orgsTotal: 1 })
    expect(body.modules.me.data.orgs).toEqual([{ id: ORG_A, name: 'Acme' }])
  })

  it('GET /api/home/:module answers the bare envelope; 403 forbidden for a module the caller may not see; 404 unknown', async () => {
    const ok = await get('/api/home/people')
    expect(ok.statusCode).toBe(200)
    expect(moduleEnvelopeSchema.safeParse(ok.json()).success).toBe(true)
    expect(ok.json().status).toBe('ok')
    const denied = await get('/api/home/health', 'orga')
    expect(denied.statusCode).toBe(403)
    expect(denied.json()).toEqual({ status: 'forbidden', asOf: null, stale: false, sources: {} })
    expect((await get('/api/home/sites', 'support')).statusCode).toBe(403)
    expect((await get('/api/home/nope')).statusCode).toBe(404)
  })
})

describe('org isolation (?org=, like the audit API orgsFor)', () => {
  it('an org admin cannot read another org — whole request and single module', async () => {
    const res = await get(`/api/home?org=${ORG_B}`, 'orga')
    expect(res.statusCode).toBe(403)
    expect(res.json().error).toBe('org_out_of_scope')
    expect((await get(`/api/home/people?org=${ORG_B}`, 'orga')).statusCode).toBe(403)
    expect(world.calls.orgMembers ?? 0).toBe(0)
  })

  it('an admin of two orgs narrows to one; the answer holds that org only', async () => {
    const all = (await warm('/api/home', 'orgab')).json()
    expect(all.modules.sites.data.list.map((s: { name: string }) => s.name).sort()).toEqual(['fleet', 'payroll'])
    const one = (await warm(`/api/home?org=${ORG_B}`, 'orgab')).json()
    expect(one.scope.org).toBe(ORG_B)
    expect(one.modules.sites.data.list.map((s: { name: string }) => s.name)).toEqual(['fleet'])
    expect(one.modules.people.data.byOrg).toEqual([{ orgId: ORG_B, name: 'Globex', members: 1 }])
  })

  it('org caches are partitioned: one org admin never receives another org set\'s cached answer', async () => {
    await warm('/api/home', 'orgab')
    const a = (await get('/api/home', 'orga')).json()
    expect(a.modules.sites.data.list.map((s: { name: string }) => s.name)).toEqual(['payroll'])
  })

  it('org admins get activity from the audit/v1 store only, filtered inside the query', async () => {
    const queries: string[] = []
    world.lokiConfigured = true
    world.loki = {
      queryRange: async (p) => { queries.push(p.query); return [] },
      instant: async (q) => { queries.push(q); return [] },
      range: async (q) => { queries.push(q); return [] },
    }
    const body = (await warm('/api/home', 'orga')).json()
    expect(body.modules.activity.status).toBe('ok')
    expect(body.modules.activity.data.source).toBe('loki')
    expect(body.modules.activity.data.topActors).toBeUndefined()
    expect(queries.length).toBeGreaterThan(0)
    for (const q of queries) {
      expect(q).toContain(`org_id="${ORG_A}"`)
      expect(q).not.toContain(ORG_B)
    }
  })

  it('without Loki an org admin is told the source is missing, never shown platform figures', async () => {
    const body = (await warm('/api/home', 'orga')).json()
    expect(body.modules.activity).toMatchObject({ status: 'unavailable', reason: 'not_deployed', connect: { setting: 'LOKI_URL' } })
    expect(body.modules.changes).toMatchObject({ status: 'unavailable', reason: 'not_deployed' })
  })
})

describe('attention — shared per scope, finished per caller', () => {
  it('four-eyes hides your own request; actionable follows sites:apply', async () => {
    const root = (await get('/api/home/attention', 'root')).json()
    const rootReqs = root.data.items.filter((i: { kind: string }) => i.kind === 'site_request_pending')
    expect(rootReqs.map((i: { subject: { id: string } }) => i.subject.id)).toEqual(['req-1'])
    expect(rootReqs[0]).toMatchObject({ actionable: true, detail: 'requested by Ada Lovelace · risk high · needs a second approver' })
    const admin = (await get('/api/home/attention', 'admin')).json()
    const adminReqs = admin.data.items.filter((i: { kind: string }) => i.kind === 'site_request_pending')
    expect(adminReqs).toHaveLength(2)
    expect(adminReqs.every((i: { actionable: boolean }) => i.actionable === false)).toBe(true)
  })

  it('sorts by severity then age, counts every item, and keeps super-admin items to super admins', async () => {
    world.outbox = { length: 40, oldestMs: Date.now() - 2 * 3_600_000 }
    const root = (await get('/api/home/attention', 'root')).json()
    const kinds = root.data.items.map((i: { kind: string }) => i.kind)
    expect(kinds).toContain('audit_archive_lag')
    const ranks = root.data.items.map((i: { severity: string }) => ({ critical: 0, warning: 1, info: 2 })[i.severity])
    expect([...ranks].sort()).toEqual(ranks)
    expect(root.data.counts.critical + root.data.counts.warning + root.data.counts.info).toBe(root.data.items.length)
    expect(kinds).toEqual(expect.arrayContaining(['site_unapplied', 'site_draft_stale', 'unassigned_users']))
    const admin = (await get('/api/home/attention', 'admin')).json()
    expect(admin.data.items.map((i: { kind: string }) => i.kind)).not.toContain('audit_archive_lag')
  })

  it('no archiver configured: a backlog raises no archive-lag alarm, only an info item near the outbox cap', async () => {
    world.archiveEnabled = false
    world.outboxMaxLen = 1_000
    world.outbox = { length: 710, oldestMs: Date.now() - 2 * 86_400_000 }
    const quiet = (await get('/api/home/attention', 'root')).json().data.items.map((i: { kind: string }) => i.kind)
    expect(quiet).not.toContain('audit_archive_lag')
    expect(quiet).not.toContain('audit_outbox_near_cap')

    invalidateHome(['attention'])
    world.outbox = { length: 950, oldestMs: Date.now() - 2 * 86_400_000 }
    const root = (await get('/api/home/attention', 'root')).json()
    const near = root.data.items.find((i: { kind: string }) => i.kind === 'audit_outbox_near_cap')
    expect(near).toMatchObject({ severity: 'info', metrics: { count: 950, cap: 1_000 }, target: { page: 'audit' } })
    expect(root.data.items.map((i: { kind: string }) => i.kind)).not.toContain('audit_archive_lag')
    const admin = (await get('/api/home/attention', 'admin')).json()
    expect(admin.data.items.map((i: { kind: string }) => i.kind)).not.toContain('audit_outbox_near_cap')
  })

  it('people findings are one counted item, from the access-review job once it has run', async () => {
    await get('/api/home/attention')
    await settle()
    invalidateHome(['attention'])
    await settle()
    const body = (await get('/api/home/attention')).json()
    const noMfa = body.data.items.find((i: { kind: string }) => i.kind === 'privileged_no_mfa')
    expect(noMfa).toMatchObject({ metrics: { count: 2 }, title: '2 people with full access have no second factor', target: { page: 'access-review', params: { filter: 'no-mfa' } } })
  })
})

describe('degradation — a dead source costs its own tile, never the response', () => {
  it('health: kube down → gateway unknown with sources.kube down; no Prometheus → certificates unknown + connect', async () => {
    world.kubeMode = 'in-cluster'
    failing('gatewayRollout')
    const body = (await warm('/api/home')).json()
    const h = body.modules.health
    expect(h.status).toBe('ok')
    const gw = h.data.components.find((c: { id: string }) => c.id === 'gateway')
    expect(gw).toMatchObject({ state: 'unknown' })
    expect(h.sources.kube).toEqual({ state: 'down' })
    expect(h.sources.prometheus).toEqual({ state: 'not_configured', connect: { setting: 'PROMETHEUS_URL', docs: 'jinbe/docs/observability.md' } })
    expect(h.data.components.find((c: { id: string }) => c.id === 'certificates')).toMatchObject({ state: 'unknown', summary: 'not connected' })
    // edge first: 1 of the 2 live sites is behind the WAF
    expect(h.data.components[0]).toMatchObject({ id: 'waf', state: 'degraded', summary: '1/2 sites behind the WAF', link: { page: 'settings', anchor: 'zones' }, metrics: { unprotected: 1, unprotectedHosts: 1 } })
    expect(h.data.components.map((c: { id: string }) => c.id)).toEqual(['waf', 'gateway', 'gateway_rules', 'opa', 'opal_data', 'kratos', 'jinbe', 'redis', 'audit_store', 'audit_archive', 'certificates'])
  })

  it('health without SITES_KUBE: gateway not_deployed, connect SITES_KUBE', async () => {
    const h = (await get('/api/home/health')).json()
    expect(h.data.components[0]).toMatchObject({ id: 'gateway', state: 'not_deployed' })
    expect(h.sources.kube).toEqual({ state: 'not_configured', connect: { setting: 'SITES_KUBE=in-cluster', docs: 'docs/SERVICE_PLUG.md' } })
  })

  it('certificates from Prometheus: soonest expiry drives the state and an attention item', async () => {
    world.prom = {
      instant: async (q) => (q.includes('ready_status') ? [] : [
        { metric: { name: 'auth-tls' }, value: 5.4 }, { metric: { name: 'other-tls' }, value: 80 },
      ]),
    }
    await get('/api/home/health')
    await settle()
    invalidateHome(['health', 'attention'])
    const h = (await get('/api/home/health')).json()
    expect(h.data.components.find((c: { id: string }) => c.id === 'certificates')).toMatchObject({ state: 'down', summary: '2 certs, soonest 5 d' })
    const a = (await get('/api/home/attention')).json()
    expect(a.data.items.find((i: { kind: string }) => i.kind === 'cert_expiring')).toMatchObject({ id: 'cert_expiring:auth-tls', severity: 'critical' })
  })

  it('no audit store at all → activity and changes unavailable/not_configured with connect LOKI_URL; the rest still 200', async () => {
    world.auditSink = 'v1'
    const res = await warm('/api/home')
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.modules.activity).toMatchObject({ status: 'unavailable', reason: 'not_configured', connect: { setting: 'LOKI_URL', docs: 'docs/OBSERVABILITY.md' } })
    expect(body.modules.people.status).toBe('ok')
  })

  it('access is not deployed until the decision log exists', async () => {
    const a = (await get('/api/home/access?window=7d')).json()
    expect(a).toMatchObject({ status: 'unavailable', reason: 'not_deployed', connect: { setting: 'opa-authz-proxy decision log (OBS-1.4)' } })
  })

  it('a source that throws turns its module source_down; others unaffected', async () => {
    failing('directoryStats')
    const body = (await get('/api/home')).json()
    expect(body.modules.people).toMatchObject({ status: 'unavailable', reason: 'source_down' })
    expect(body.modules.sites.status).toBe('ok')
  })

  it('a source that hangs costs its budget only: the module answers warming, the response stays fast', async () => {
    hanging('siteRows')
    const started = Date.now()
    const res = await get('/api/home')
    expect(Date.now() - started).toBeLessThan(1_500)
    expect(res.statusCode).toBe(200)
    expect(res.json().modules.sites).toMatchObject({ status: 'unavailable', reason: 'warming' })
    expect(res.json().modules.people.status).toBe('ok')
  })

  it('a background module never waits on its source: a hanging Loki answers warming at once', async () => {
    world.lokiConfigured = true
    const never = () => new Promise<never>(() => {})
    world.loki = { queryRange: never, instant: never, range: never }
    const started = Date.now()
    const body = (await get('/api/home/activity')).json()
    expect(Date.now() - started).toBeLessThan(400)
    expect(body).toMatchObject({ status: 'unavailable', reason: 'warming', asOf: null })
  })
})

describe('SWR cache (§3.6)', () => {
  it('background modules warm, then serve from the cache without recomputing', async () => {
    world.legacyRows = [
      [`${Date.now() - 60_000}-0`, ['category', 'auth', 'kind', 'auth', 'verb', 'login', 'result', 'ok', 'actor', '{"email":"ada@example.com"}']],
      [`${Date.now() - 50_000}-0`, ['category', 'auth', 'kind', 'auth', 'verb', 'login', 'result', 'denied', 'actor', '{}']],
      [`${Date.now() - 40_000}-0`, ['category', 'rbac', 'kind', 'change', 'verb', 'assign', 'result', 'ok', 'actor', '{}']],
      [`${Date.now() - 30_000}-0`, ['category', 'access', 'kind', 'access', 'verb', 'deny', 'result', 'denied', 'target', 'GET /api/admin/users/:email', 'actor', '{}']],
      [`${Date.now() - 20_000}-0`, ['category', 'access', 'kind', 'access', 'verb', 'deny', 'result', 'denied', 'target', 'GET /api/admin/users/x@y.com', 'actor', '{}']],
    ]
    const first = (await get('/api/home/activity')).json()
    expect(first).toMatchObject({ status: 'unavailable', reason: 'warming' })
    await settle()
    const second = (await get('/api/home/activity')).json()
    expect(second).toMatchObject({ status: 'ok', stale: false })
    expect(second.data).toMatchObject({
      source: 'redis-legacy',
      signIns: { succeeded: 1, failed: 1, distinctUsers: 1, failedFactor: null, failedSpike: null },
      denied: { total: 2 },
      topDeniedRoutes: [{ route: 'GET /api/admin/users/:email', count: 1 }],
    })
    expect(second.data.series).toHaveLength(24)
    expect(second.data.series.reduce((a: number, b: { changes: number }) => a + b.changes, 0)).toBe(1)
    const calls = world.calls.legacyRows
    await get('/api/home/activity')
    expect(world.calls.legacyRows).toBe(calls)
  })

  it('past the fresh window: served stale with the last good value, one refresh started', async () => {
    await get('/api/home/people')
    const key = [...redisHolder.redis.kv.keys()].find((k) => k.startsWith('home:v1:people:'))!
    const stored = JSON.parse(redisHolder.redis.kv.get(key)!.v)
    stored.asOf -= 60_000
    redisHolder.redis.kv.set(key, { v: JSON.stringify(stored), exp: null })
    world.stats = { ...world.stats!, total: 99 }
    const stale = (await get('/api/home/people')).json()
    expect(stale).toMatchObject({ status: 'ok', stale: true, data: { identities: 12 } })
    await settle()
    const fresh = (await get('/api/home/people')).json()
    expect(fresh).toMatchObject({ status: 'ok', stale: false, data: { identities: 99 } })
  })

  it('a refresh that fails keeps the last good value (stale), never overwrites it with an error', async () => {
    await get('/api/home/people')
    const key = [...redisHolder.redis.kv.keys()].find((k) => k.startsWith('home:v1:people:'))!
    const stored = JSON.parse(redisHolder.redis.kv.get(key)!.v)
    stored.asOf -= 60_000
    redisHolder.redis.kv.set(key, { v: JSON.stringify(stored), exp: null })
    failing('directoryStats')
    await get('/api/home/people')
    await settle()
    const again = (await get('/api/home/people')).json()
    expect(again).toMatchObject({ status: 'ok', stale: true, data: { identities: 12 } })
  })

  it('platform modules are computed once for every platform reader', async () => {
    await get('/api/home/sites', 'root')
    const n = world.calls.siteRows
    await get('/api/home/sites', 'admin')
    expect(world.calls.siteRows).toBe(n)
  })

  it('invalidateHome drops a module: the next read recomputes', async () => {
    await get('/api/home/sites')
    const n = world.calls.siteRows
    invalidateHome(['sites'])
    await settle()
    world.siteRows = world.siteRows.slice(0, 1)
    const body = (await get('/api/home/sites')).json()
    expect(world.calls.siteRows).toBe(n + 1)
    expect(body.data.list).toHaveLength(1)
  })
})

describe('activity from audit/v1 (Loki) for platform readers', () => {
  it('sign-ins, top actors by display name, and a failed sign-in spike raised in the queue', async () => {
    world.lokiConfigured = true
    const hourly: Array<[number, number]> = Array.from({ length: 169 }, (_, i) => [i, i === 168 ? 40 : 5])
    world.loki = {
      queryRange: async () => [],
      instant: async (q, at) => {
        if (q.startsWith('count(')) return [{ metric: {}, value: 7 }]
        if (q.includes('sum by (event)')) {
          const prev = at < Date.now() / 1000 - 3600
          return [{ metric: { event: 'auth.login.succeeded' }, value: prev ? 30 : 42 }, { metric: { event: 'auth.login.failed' }, value: prev ? 4 : 40 }]
        }
        if (q.includes('sum by (actor_id)')) return [{ metric: { actor_id: 'id-ada' }, value: 9 }, { metric: { actor_id: 'ghost' }, value: 1 }]
        if (q.includes('sum by (target_id)')) return [{ metric: { target_id: 'GET /api/admin/users/:email' }, value: 3 }, { metric: { target_id: 'GET /x/a@b.c' }, value: 1 }]
        return []
      },
      range: async (q) => (q.includes('[3600s]') ? [{ metric: {}, values: hourly }] : []),
    }
    const a = (await warm('/api/home/activity')).json()
    expect(a.status).toBe('ok')
    expect(a.data).toMatchObject({
      source: 'loki',
      signIns: { succeeded: 42, failed: 40, prevSucceeded: 30, prevFailed: 4, distinctUsers: 7, failedFactor: 8, failedSpike: { factor: 8, current: 40, baseline: 5 } },
      topActors: [{ actorId: 'id-ada', label: 'Ada Lovelace', count: 9 }, { actorId: 'ghost', label: 'Unknown user', count: 1 }],
      topDeniedRoutes: [{ route: 'GET /api/admin/users/:email', count: 3 }],
    })
    const q = (await get('/api/home/attention')).json()
    expect(q.data.items.find((i: { kind: string }) => i.kind === 'login_failure_spike')).toMatchObject({ severity: 'warning', title: 'Failed sign-ins are 8× usual', metrics: { factor: 8, current: 40, baseline: 5 } })
  })
})
