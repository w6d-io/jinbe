import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { ACME, payrollSite } from './fixtures.js'
import { fakeGatekit } from './mocks.js'

// S-2: /api/admin/sites. Writes need admin:write (super_admin); apply, rollback, pause/resume and
// delete also need a recent second factor. Permissions are published BEFORE the Site CR, and when
// gatekit or the Kubernetes API cannot answer, the answer is 503 and nothing is written.

const h = vi.hoisted(() => ({
  invalidate: vi.fn(),
  emit: vi.fn(),
  kube: {
    up: true,
    ping: vi.fn(),
    get: vi.fn(async () => null),
    apply: vi.fn(),
    delete: vi.fn(),
  },
  gatekit: {
    compile: (patterns: Array<{ id: string }>) => ({ results: patterns.map((p) => ({ id: p.id, ok: true })) }) as unknown,
    overlap: (_b: unknown) => ({ overlaps: [] }) as unknown,
    status: 200,
    calls: [] as Array<{ path: string; body: Record<string, unknown> }>,
  },
  grants: {} as Record<string, Record<string, string[]>>,
}))

vi.mock('../../services/redis-client.service.js', async () => {
  const { InlineRedisMock } = await import('./mocks.js')
  const redis = new InlineRedisMock()
  return { getRedisClient: () => redis, __redis: redis }
})
vi.mock('../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => Promise<unknown>) => fn() }))
vi.mock('../../services/redis-rbac.repository.js', async () => {
  const { makeRbacStore } = await import('./mocks.js')
  const store = makeRbacStore()
  return { redisRbacRepository: store.repo, __store: store }
})
vi.mock('../../services/rbac.service.js', () => ({ rbacService: { invalidateBundle: h.invalidate } }))
vi.mock('../../services/org-grants.repository.js', () => ({ orgGrantsRepository: { getAll: vi.fn(async () => h.grants) } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../middleware/require-admin.js', async () => {
  const { enforcing } = await import('../../policy/declared-routes.js')
  return {
  requireSuperAdmin: enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden', message: 'needs admin:write' })
  }, 'admin:write'),
  requireSitesApply: enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden', message: 'needs sites:apply' })
  }, 'sites:apply'),
  requireRecentMfa: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-mfa']) return reply.status(422).send({ error: 'reauth_required', message: 'mfa' })
  },
  }
})

import { sitesRoutes } from '../../sites/routes.js'
import { setKubeSites, KubeUnavailable } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import * as redisClient from '../../services/redis-client.service.js'
import * as rbacRepo from '../../services/redis-rbac.repository.js'
import { declaredRoutes, enforcing, guardAll, resetDeclaredRoutes } from '../../policy/declared-routes.js'

type Store = ReturnType<typeof import('./mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('./mocks.js').InlineRedisMock }).__redis

let app: FastifyInstance
const W = { 'x-test-write': '1' }
const WM = { 'x-test-write': '1', 'x-test-mfa': '1' }

beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request) => {
    request.userContext = { id: 'sam-id', email: 'sam@x.test', name: 'Sam' }
  })
  await app.register(sitesRoutes, { prefix: '/sites' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  redis.clear()
  store.reset()
  h.grants = {}
  h.gatekit.status = 200
  h.gatekit.calls = []
  h.gatekit.compile = (patterns: Array<{ id: string }>) => ({ results: patterns.map((p) => ({ id: p.id, ok: true })) })
  h.gatekit.overlap = () => ({ overlaps: [] })
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_KUBE = 'off'
  process.env.SITES_ZONES = '[{"suffix":"dev.stairling.com","wildcardTls":true,"exposure":"ingress"}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.stairling.com'
  process.env.SITES_RESERVED_HOSTS = 'kuma.dev.stairling.com'
  resetSitesConfig()
  h.kube.ping.mockImplementation(async () => { if (!h.kube.up) throw new KubeUnavailable('down') })
  h.kube.apply.mockImplementation(async () => { store.s.log.push('kube.apply') })
  h.kube.delete.mockImplementation(async () => { store.s.log.push('kube.delete') })
  h.kube.up = true
  setKubeSites(h.kube)
  h.invalidate.mockImplementation(async () => { store.s.log.push('invalidateBundle') })
  vi.stubGlobal('fetch', fakeGatekit(h.gatekit))
})

const save = async (site = payrollSite(), headers: Record<string, string> = W) =>
  app.inject({ method: 'PUT', url: `/sites/${site.name}`, headers, payload: { site, note: 'v' } })

describe('guards', () => {
  it('publishes its route table rows: reads under the admin plugin gate, writes admin:write', async () => {
    resetDeclaredRoutes()
    const admin = Fastify()
    await admin.register(async (scope) => {
      guardAll(scope, enforcing(async () => {}, 'admin:read'), () => false)
      await scope.register(sitesRoutes, { prefix: '/sites' })
    }, { prefix: '/api/admin' })
    await admin.ready()
    const rows = declaredRoutes().filter((r) => r.path.startsWith('/api/admin/sites'))
    const find = (method: string, path: string) => rows.find((r) => r.method === method && r.path === path)?.permission
    expect(find('GET', '/api/admin/sites')).toBe('admin:read')
    expect(find('GET', '/api/admin/sites/:name/blast-radius')).toBe('admin:read')
    expect(find('PUT', '/api/admin/sites/:name')).toBe('admin:write')
    expect(find('POST', '/api/admin/sites/:name/apply')).toBe('sites:apply')
    expect(find('POST', '/api/admin/sites/preview')).toBe('admin:write')
    expect(rows.every((r) => r.class === 'authorized')).toBe(true)
    await admin.close()
  })

  it('a write without admin:write is refused and writes nothing', async () => {
    const res = await save(payrollSite(), {})
    expect(res.statusCode).toBe(403)
    expect(redis.hashes.size).toBe(0)
  })

  it('apply without a recent second factor is refused and writes nothing', async () => {
    await save()
    const res = await app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: W, payload: { version: 1 } })
    expect(res.statusCode).toBe(422)
    expect(store.s.log).toEqual([])
  })

  it.each(['rollback', 'pause', 'resume'])('%s needs a recent second factor', async (action) => {
    const res = await app.inject({ method: 'POST', url: `/sites/payroll/${action}`, headers: W, payload: { toVersion: 1 } })
    expect(res.statusCode).toBe(422)
  })

  it('delete needs a recent second factor', async () => {
    expect((await app.inject({ method: 'DELETE', url: '/sites/payroll', headers: W })).statusCode).toBe(422)
  })

  it.each(['jinbe', 'kuma', 'global'])('system site %s is untouchable', async (name) => {
    const put = await app.inject({ method: 'PUT', url: `/sites/${name}`, headers: W, payload: { site: payrollSite({ name }) } })
    expect(put.statusCode).toBe(403)
    expect((await app.inject({ method: 'PUT', url: `/sites/${name}/draft`, headers: W, payload: { site: {} } })).statusCode).toBe(403)
    expect((await app.inject({ method: 'DELETE', url: `/sites/${name}`, headers: WM })).statusCode).toBe(403)
    expect((await app.inject({ method: 'POST', url: `/sites/${name}/apply`, headers: WM, payload: { version: 1 } })).statusCode).toBe(403)
  })
})

describe('save, list, get, versions', () => {
  it('saves version 1 with an ETag and lists it as a draft', async () => {
    const res = await save()
    expect(res.statusCode).toBe(200)
    expect(res.headers.etag).toMatch(/^"[0-9a-f]{16}"$/)
    expect(res.json()).toMatchObject({ version: 1 })
    const list = (await app.inject({ method: 'GET', url: '/sites' })).json()
    expect(list).toMatchObject([{ name: 'payroll', host: 'payroll.dev.stairling.com', status: 'draft', version: 1 }])
    const one = await app.inject({ method: 'GET', url: '/sites/payroll' })
    expect(one.json()).toMatchObject({ site: { name: 'payroll' }, version: 1, status: 'draft' })
    expect(one.headers.etag).toBe(res.headers.etag)
  })

  it('refuses a missing or stale If-Match on an existing site', async () => {
    const first = await save()
    expect((await save()).statusCode).toBe(428)
    const stale = await app.inject({ method: 'PUT', url: '/sites/payroll', headers: { ...W, 'if-match': '"0000000000000000"' }, payload: { site: payrollSite() } })
    expect(stale.statusCode).toBe(412)
    const ok = await app.inject({ method: 'PUT', url: '/sites/payroll', headers: { ...W, 'if-match': first.headers.etag as string }, payload: { site: payrollSite() } })
    expect(ok.statusCode).toBe(200)
    const versions = (await app.inject({ method: 'GET', url: '/sites/payroll/versions' })).json()
    expect(versions.map((v: { v: number }) => v.v)).toEqual([1, 2])
    expect(versions[0]).toMatchObject({ by: 'sam@x.test', kind: 'save' })
    expect(versions[0].site).toBeUndefined()
  })

  it('rejects an invalid intent with the zod issues', async () => {
    const res = await app.inject({ method: 'PUT', url: '/sites/payroll', headers: W, payload: { site: { ...payrollSite(), address: { host: 'not a host' } } } })
    expect(res.statusCode).toBe(400)
    expect(res.json().issues.length).toBeGreaterThan(0)
  })

  it('rejects a body naming another site', async () => {
    const res = await app.inject({ method: 'PUT', url: '/sites/other', headers: W, payload: { site: payrollSite() } })
    expect(res.statusCode).toBe(400)
  })

  it('refuses to save an intent that does not render', async () => {
    const site = payrollSite()
    site.routes.items[1] = { ...site.routes.items[1], orgParam: 'nope' }
    const res = await save(site)
    expect(res.statusCode).toBe(422)
    expect(res.json().checks.map((c: { code: string }) => c.code)).toContain('org_param')
  })

  it('refuses a name already used by a legacy service', async () => {
    store.s.services.add('payroll')
    expect((await save()).statusCode).toBe(409)
  })
})

describe('drafts', () => {
  it('put, get and drop a draft (may be incomplete)', async () => {
    const put = await app.inject({ method: 'PUT', url: '/sites/payroll/draft', headers: W, payload: { site: { name: 'payroll' }, baseVersion: 0 } })
    expect(put.statusCode).toBe(200)
    const got = (await app.inject({ method: 'GET', url: '/sites/payroll/draft' })).json()
    expect(got).toMatchObject({ site: { name: 'payroll' }, baseVersion: 0, updatedBy: 'sam@x.test' })
    expect((await app.inject({ method: 'DELETE', url: '/sites/payroll/draft', headers: W })).statusCode).toBe(204)
    expect((await app.inject({ method: 'GET', url: '/sites/payroll/draft' })).statusCode).toBe(404)
  })

  it('a draft naming another site is refused', async () => {
    const put = await app.inject({ method: 'PUT', url: '/sites/payroll/draft', headers: W, payload: { site: { name: 'billing' } } })
    expect(put.statusCode).toBe(400)
  })
})

describe('preview', () => {
  it('renders and runs gatekit compile + overlap against every live rule, system ones included', async () => {
    store.s.accessRules = [{ id: 'kuma-api', upstream: { url: 'http://j' }, match: { url: 'http<(s?)>://kuma.dev.stairling.com/api/<.*>', methods: ['GET'] }, authenticators: [], authorizer: { handler: 'allow' }, mutators: [] }]
    const res = await app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site: payrollSite() } })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.artefacts.routeMap.length).toBeGreaterThan(0)
    expect(body.artefacts.siteCr.kind).toBe('Site')
    expect(body.risk.level).toBeDefined()
    const overlap = h.gatekit.calls.find((c) => c.path === '/overlap')!
    expect((overlap.body.rules as Array<{ id: string }>).map((r) => r.id)).toContain('kuma-api')
    expect((overlap.body.probes as unknown[]).length).toBeGreaterThan(0)
    expect(overlap.body).toMatchObject({ strategy: 'regexp', hosts: ['payroll.dev.stairling.com'] })
  })

  it('reports an overlap with a live rule as an error', async () => {
    h.gatekit.overlap = (body: unknown) => {
      const rules = (body as { rules: Array<{ id: string }> }).rules
      return { overlaps: [{ a: rules.at(-1)!.id, b: 'kuma-api', method: 'GET', exampleUrl: 'https://payroll.dev.stairling.com/' }] }
    }
    const body = (await app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site: payrollSite() } })).json()
    expect(body.checks.filter((c: { level: string }) => c.level === 'error').map((c: { code: string }) => c.code)).toContain('rule_overlap')
  })

  it('reports a rule the matcher refuses while probing', async () => {
    h.gatekit.overlap = (body: unknown) => ({ overlaps: [], invalid: [{ id: (body as { rules: Array<{ id: string }> }).rules.at(-1)!.id, error: 'bad regex' }] })
    const body = (await app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site: payrollSite() } })).json()
    expect(body.checks.map((c: { code: string }) => c.code)).toContain('pattern_invalid')
  })

  it('reports a pattern gatekit cannot compile', async () => {
    h.gatekit.compile = (patterns: Array<{ id: string }>) => ({ results: patterns.map((p, i) => ({ id: p.id, ok: i !== 0, error: 'bad' })) })
    const body = (await app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site: payrollSite() } })).json()
    expect(body.checks.map((c: { code: string }) => c.code)).toContain('pattern_invalid')
  })

  it('answers 503 when gatekit is unset or down', async () => {
    delete process.env.GATEKIT_URL
    resetSitesConfig()
    const unset = await app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site: payrollSite() } })
    expect(unset.statusCode).toBe(503)
    expect(unset.json().error).toBe('checks_unavailable')
    process.env.GATEKIT_URL = 'http://gatekit:8080'
    resetSitesConfig()
    h.gatekit.status = 500
    expect((await app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site: payrollSite() } })).statusCode).toBe(503)
  })
})

describe('apply', () => {
  const apply = (version = 1) => app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: WM, payload: { version } })

  it('publishes permissions first, then writes the Site CR', async () => {
    await save()
    const res = await apply()
    expect(res.statusCode).toBe(200)
    expect(store.s.routeMaps.payroll.rules.length).toBeGreaterThan(0)
    expect(store.s.roles.payroll).toMatchObject({ admin: ['*'] })
    expect(store.s.services.has('payroll')).toBe(true)
    expect(store.s.groups.admins).toEqual({ kuma: ['admin'], payroll: ['admin'] })
    expect(store.s.groups['payroll-editors']).toEqual({ payroll: ['editor'] })
    expect(store.s.orgMap[ACME]).toEqual(['payroll'])
    const log = store.s.log
    expect(log.indexOf('invalidateBundle')).toBeGreaterThan(log.indexOf('setRouteMap:payroll'))
    expect(log.indexOf('kube.apply')).toBeGreaterThan(log.indexOf('invalidateBundle'))
    const cr = h.kube.apply.mock.calls[0][0] as { metadata: { annotations: Record<string, string> }; spec: { gates: unknown[] } }
    expect(cr.metadata.annotations['auth.w6d.io/version']).toBe('1')
    expect(cr.spec.gates.length).toBe(3)
    expect((cr.spec.gates as Array<{ name: string; match: { url: string } }>).every((g) => g.match.url.startsWith('<https?>://payroll.dev.stairling.com/'))).toBe(true)
    const listed = (await app.inject({ method: 'GET', url: '/sites' })).json()
    expect(listed[0]).toMatchObject({ status: 'live', appliedBy: 'sam@x.test' })
    expect(h.emit).toHaveBeenCalled()
  })

  it('refuses to apply a version that is not the saved one', async () => {
    await save()
    expect((await apply(2)).statusCode).toBe(409)
  })

  it('gatekit down → 503, nothing published, no CR', async () => {
    await save()
    h.gatekit.status = 502
    const res = await apply()
    expect(res.statusCode).toBe(503)
    expect(store.s.log).toEqual([])
    expect(h.kube.apply).not.toHaveBeenCalled()
  })

  it('Kubernetes down → 503, nothing published', async () => {
    await save()
    h.kube.up = false
    const res = await apply()
    expect(res.statusCode).toBe(503)
    expect(res.json().error).toBe('kubernetes_unavailable')
    expect(store.s.log).toEqual([])
  })

  it('a route tie with another service → 409, nothing published', async () => {
    store.s.services.add('legacy')
    store.s.routeMaps.legacy = { rules: [{ method: 'GET', path: '/health' }] }
    await save()
    const res = await apply()
    expect(res.statusCode).toBe(409)
    expect(store.s.log).toEqual([])
  })

  it('an overlap found by gatekit → 409, nothing published', async () => {
    await save()
    h.gatekit.overlap = (body: unknown) => {
      const rules = (body as { rules: Array<{ id: string }> }).rules
      return { overlaps: [{ a: rules.at(-1)!.id, b: 'other', method: 'GET', exampleUrl: 'https://payroll.dev.stairling.com/' }] }
    }
    expect((await apply()).statusCode).toBe(409)
    expect(store.s.log).toEqual([])
  })

  it('a platform group that does not exist → 409, nothing published', async () => {
    const site = payrollSite()
    site.groups.platform.ghosts = ['viewer']
    await save(site)
    expect((await apply()).statusCode).toBe(409)
    expect(store.s.log).toEqual([])
  })
})

describe('rollback, pause, delete, blast radius', () => {
  const applyV = (v: number) => app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: WM, payload: { version: v } })

  it('rollback saves the old version as a new one and applies it', async () => {
    const first = await save()
    await applyV(1)
    await app.inject({ method: 'PUT', url: '/sites/payroll', headers: { ...W, 'if-match': first.headers.etag as string }, payload: { site: payrollSite({ displayName: 'Two' }) } })
    await applyV(2)
    const res = await app.inject({ method: 'POST', url: '/sites/payroll/rollback', headers: WM, payload: { toVersion: 1 } })
    expect(res.statusCode).toBe(200)
    const versions = (await app.inject({ method: 'GET', url: '/sites/payroll/versions' })).json()
    expect(versions.at(-1)).toMatchObject({ v: 3, kind: 'rollback' })
    const one = (await app.inject({ method: 'GET', url: '/sites/payroll' })).json()
    expect(one).toMatchObject({ version: 3, status: 'live', site: { displayName: 'Payroll' } })
  })

  it('pause writes a paused CR and keeps the permissions', async () => {
    await save()
    await applyV(1)
    const res = await app.inject({ method: 'POST', url: '/sites/payroll/pause', headers: WM })
    expect(res.statusCode).toBe(200)
    const cr = h.kube.apply.mock.calls.at(-1)![0] as { spec: { paused: boolean } }
    expect(cr.spec.paused).toBe(true)
    expect((await app.inject({ method: 'GET', url: '/sites' })).json()[0].status).toBe('paused')
    expect(store.s.routeMaps.payroll).toBeDefined()
    await app.inject({ method: 'POST', url: '/sites/payroll/resume', headers: WM })
    expect((h.kube.apply.mock.calls.at(-1)![0] as { spec: { paused: boolean } }).spec.paused).toBe(false)
  })

  it('pause with Kubernetes down changes nothing', async () => {
    await save()
    await applyV(1)
    h.kube.up = false
    expect((await app.inject({ method: 'POST', url: '/sites/payroll/pause', headers: WM })).statusCode).toBe(503)
    expect((await app.inject({ method: 'GET', url: '/sites' })).json()[0].status).toBe('live')
  })

  it('blast radius names the groups, orgs, grants, rules and routes', async () => {
    await save()
    await applyV(1)
    h.grants = { [ACME]: { 'bob@acme.test': ['payroll-editors'], 'eve@acme.test': ['other'] } }
    const res = await app.inject({ method: 'GET', url: '/sites/payroll/blast-radius' })
    expect(res.json()).toMatchObject({
      groups: ['admins'],
      orgGrantableGroups: ['payroll-editors'],
      orgs: [{ id: ACME, grants: 1 }],
      rules: 3,
    })
    expect(res.json().routes).toBeGreaterThan(0)
  })

  it('delete removes the CR first, then every derived permission, and keeps a snapshot', async () => {
    await save()
    await applyV(1)
    store.s.log = []
    const res = await app.inject({ method: 'DELETE', url: '/sites/payroll', headers: WM })
    expect(res.statusCode).toBe(200)
    expect(store.s.log[0]).toBe('kube.delete')
    expect(store.s.routeMaps.payroll).toBeUndefined()
    expect(store.s.services.has('payroll')).toBe(false)
    expect(store.s.groups.admins).toEqual({ kuma: ['admin'] })
    expect(store.s.groups['payroll-editors']).toBeUndefined()
    expect(store.s.orgMap[ACME]).toBeUndefined()
    expect((await app.inject({ method: 'GET', url: '/sites/payroll' })).statusCode).toBe(404)
    expect(redis.strings.has('rbac:sites:deleted:payroll')).toBe(true)
  })

  it('delete with Kubernetes down changes nothing', async () => {
    await save()
    await applyV(1)
    store.s.log = []
    h.kube.up = false
    expect((await app.inject({ method: 'DELETE', url: '/sites/payroll', headers: WM })).statusCode).toBe(503)
    expect(store.s.log).toEqual([])
    expect((await app.inject({ method: 'GET', url: '/sites/payroll' })).statusCode).toBe(200)
  })
})

describe('diff, check-host, match, render', () => {
  it('diff against nothing applied lists every artefact as added', async () => {
    await save()
    const res = await app.inject({ method: 'POST', url: '/sites/payroll/diff', headers: W, payload: {} })
    expect(res.statusCode).toBe(200)
    const kinds = res.json().artefacts.map((a: { kind: string }) => a.kind)
    expect(kinds).toEqual(expect.arrayContaining(['routeMap', 'roles', 'groups', 'orgServiceMap', 'rules']))
    expect(res.json().risk.flags.length).toBeGreaterThan(0)
  })

  it('check-host resolves the host against the zones and reports SSO coverage', async () => {
    const res = await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'new.dev.stairling.com' } })
    expect(res.json()).toMatchObject({ available: true, zone: 'dev.stairling.com', sso: true, modes: ['zone', 'vanity'], reserved: false })
    const out = (await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'payroll.example.com' } })).json()
    expect(out).toMatchObject({ available: false, zone: null, modes: [] })
  })

  it('GET /zones lists the configured zones with their SSO coverage', async () => {
    process.env.SITES_ZONES = '[{"suffix":"dev.stairling.com"},{"suffix":"dev.stairfleet.com","cookieDomain":".stairfleet.com"},{"suffix":"apps.example.org"}]'
    resetSitesConfig()
    expect((await app.inject({ method: 'GET', url: '/sites/zones' })).json()).toEqual([
      { suffix: 'dev.stairling.com', wildcard: '*.dev.stairling.com', cookieDomain: '.dev.stairling.com', sso: true, tls: 'wildcard', source: 'config' },
      { suffix: 'dev.stairfleet.com', wildcard: '*.dev.stairfleet.com', cookieDomain: '.stairfleet.com', sso: true, tls: 'wildcard', source: 'config' },
      { suffix: 'apps.example.org', wildcard: '*.apps.example.org', cookieDomain: '.dev.stairling.com', sso: false, tls: 'wildcard', source: 'config' },
    ])
  })

  it('check-host: a reserved platform host or another site is not available', async () => {
    expect((await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'kuma.dev.stairling.com' } })).json()).toMatchObject({ available: false, reserved: true })
    await save()
    const taken = (await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'payroll.dev.stairling.com' } })).json()
    expect(taken).toMatchObject({ available: false, owner: 'payroll' })
    const self = (await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'payroll.dev.stairling.com', site: 'payroll' } })).json()
    expect(self.available).toBe(true)
  })

  it('match asks gatekit about the draft and says which route and permission apply', async () => {
    const res = await app.inject({
      method: 'POST', url: '/sites/match', headers: W,
      payload: { method: 'GET', url: 'https://payroll.dev.stairling.com/api/orgs/acme/payslips', against: 'draft', site: payrollSite() },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({
      gateway: { verdict: 'one' },
      route: { method: 'GET', path: '/api/orgs/:orgId/payslips', permission: 'payslips:read', org_param: 'orgId' },
      needs: 'payslips:read',
      org: 'acme',
    })
    const call = h.gatekit.calls.find((c) => c.path === '/match')!
    expect(call.body).toMatchObject({ strategy: 'regexp', method: 'GET', url: 'https://payroll.dev.stairling.com/api/orgs/acme/payslips' })
  })

  it('render proxies to gatekit and answers 503 when it is down', async () => {
    const payload = { template: '{{ print .Subject }}', kind: 'header', sample: { subject: 'id-1', email: 'a@b.test', aal: 'aal2', method: 'GET', url: 'https://x.dev.stairling.com/', pattern: '<https?>://x.dev.stairling.com/<.*>' } }
    expect((await app.inject({ method: 'POST', url: '/sites/render', headers: W, payload })).json()).toEqual({ value: 'rendered', bytes: 8 })
    const sent = h.gatekit.calls.find((c) => c.path === '/render')!.body
    expect(sent).toMatchObject({
      kind: 'header',
      sample: {
        subject: 'id-1',
        extra: { identity: { id: 'id-1', traits: { email: 'a@b.test' } }, authenticator_assurance_level: 'aal2' },
        matchContext: { method: 'GET', url: 'https://x.dev.stairling.com/', pattern: '<https?>://x.dev.stairling.com/<.*>' },
      },
    })
    h.gatekit.status = 400
    expect((await app.inject({ method: 'POST', url: '/sites/render', headers: W, payload })).json()).toEqual({ value: '', bytes: 0, error: 'rejected' })
    h.gatekit.status = 503
    expect((await app.inject({ method: 'POST', url: '/sites/render', headers: W, payload })).statusCode).toBe(503)
  })
})
