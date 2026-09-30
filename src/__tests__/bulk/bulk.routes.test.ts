import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// /api/admin/bulk/<op>/{plan,execute} and /bulk/jobs/:id: a dry run judged against the caller's
// rights, an execute that needs the plan's hash (and refuses a plan whose outcome changed), per-item
// results, each item re-checked right before it runs, idempotent and resumable. Each op's routes
// declare its own permission, so a key's scope is checked per operation. Nothing is ever deleted.

const ME = '99999999-9999-4999-8999-999999999999'
const U1 = '11111111-1111-4111-8111-111111111111'
const U2 = '22222222-2222-4222-8222-222222222222'

const h = vi.hoisted(() => ({
  redis: new Map<string, string>(),
  identities: new Map<string, Record<string, unknown>>(),
  groups: new Map<string, string[]>(),
  facts: {} as Record<string, { declared: boolean; everyOrganisation: boolean; empty: boolean }>,
  grants: [] as Array<Record<string, unknown>>,
  created: [] as Array<Record<string, unknown>>,
  sends: [] as string[],
  drafts: [] as Array<{ name: string; site: Record<string, unknown> }>,
  site: null as Record<string, unknown> | null,
  emits: [] as Array<Record<string, unknown>>,
}))

vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    get: async (k: string) => h.redis.get(k) ?? null,
    set: async (k: string, v: string, ...args: unknown[]) => {
      if (args.includes('NX') && h.redis.has(k)) return null
      h.redis.set(k, v)
      return 'OK'
    },
    del: async (k: string) => (h.redis.delete(k) ? 1 : 0),
    expire: async () => 1,
    ttl: async () => 60,
    incr: async (k: string) => { const n = Number(h.redis.get(k) ?? 0) + 1; h.redis.set(k, String(n)); return n },
  }),
}))
vi.mock('../../services/kratos.service.js', async (importOriginal) => {
  const { KratosApiError } = await importOriginal<typeof import('../../services/kratos.service.js')>()
  return {
    KratosApiError,
    kratosService: {
      getIdentity: vi.fn(async (id: string) => {
        const i = h.identities.get(id)
        if (!i) throw new KratosApiError(404, 'nope')
        return structuredClone(i)
      }),
      findByEmail: vi.fn(async (email: string) => [...h.identities.values()].find((i) => (i.traits as { email: string }).email === email) ?? null),
      createIdentity: vi.fn(async (body: Record<string, unknown>) => { h.created.push(body); return { id: `new-${h.created.length}`, ...body } }),
      sendRecoveryEmail: vi.fn(async () => {}),
    },
  }
})
vi.mock('../../services/organisation-store.js', () => ({ groupsForSubjects: vi.fn(async (ids: string[]) => new Map(ids.map((id) => [id, h.groups.get(id) ?? []]))) }))
vi.mock('../../services/group-catalogue.js', () => ({
  groupFacts: vi.fn(async (names: string[]) => new Map(names.map((n) => [n, h.facts[n] ?? { declared: false, everyOrganisation: false, empty: true }]))),
}))
vi.mock('../../services/user-groups.service.js', () => ({
  userGroupsService: { applyGroupUpdate: vi.fn(async (input: Record<string, unknown>) => { h.grants.push(input); return { ok: true, response: {} } }) },
}))
vi.mock('../../services/rbac.service.js', () => ({ rbacService: { invalidateDirectoryStats: vi.fn(async () => {}) } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async (e: Record<string, unknown>) => { h.emits.push(e); return '1-0' }) } }))
vi.mock('../../audit/deny.js', () => ({ denyAudit: vi.fn() }))
vi.mock('../../sites/repository.js', () => ({
  sitesRepository: { get: vi.fn(async () => (h.site ? { site: structuredClone(h.site), version: 3 } : null)), getDraft: vi.fn(async () => null) },
}))
vi.mock('../../sites/sites.service.js', () => ({
  putDraft: vi.fn(async (name: string, body: { site: Record<string, unknown> }) => { h.drafts.push({ name, site: structuredClone(body.site) }); return body }),
}))
vi.mock('../../sites/audit.js', () => ({ auditSite: vi.fn() }))
vi.mock('../../middleware/require-permission.js', async () => (await import('../helpers/permission-stand-ins.js')).permissionStandIn({ readsOpen: false }))
vi.mock('../../middleware/require-admin.js', async () => (await import('../helpers/permission-stand-ins.js')).adminStandIn())

import { installRouteAccess } from '../../policy/route-access.js'
import { delegationGate } from '../../middleware/delegation-gate.js'
import { bulkRoutes } from '../../bulk/routes.js'
import { running } from '../../bulk/engine.js'
import { declaredRoutes } from '../../policy/declared-routes.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const scopes = request.headers['x-scopes'] as string | undefined
    const perms = String(request.headers['x-test-perms'] ?? '').split(',').filter(Boolean)
    request.userContext = {
      id: String(request.headers['x-user'] ?? ME), email: 'me@x.test', name: 'Me',
      ...(scopes !== undefined
        ? { authVia: 'delegated' as const, delegation: { clientId: 'claude', scopes: scopes.split(' ').filter(Boolean), kind: 'personal' as const, via: 'auth-mcp', ...(request.headers['x-key-step-up'] ? { keyStepUpAt: String(request.headers['x-key-step-up']) } : {}) } }
        : { authVia: 'session' as const }),
    } as never
    request.rbacInfo = { email: 'me@x.test', groups: [], roles: [], permissions: perms } as never
  })
  app.addHook('preHandler', delegationGate)
  await app.register(bulkRoutes, { prefix: '/api/admin/bulk' })
  await app.ready()
})
afterAll(() => app.close())

const settle = async () => { await Promise.all([...running.values()]) }
const ident = (id: string, email: string, verified: boolean) => ({
  id, schema_id: 'default', traits: { email }, verifiable_addresses: [{ id, value: email, verified, via: 'email', status: verified ? 'completed' : 'pending' }],
})

beforeEach(() => {
  h.redis.clear()
  h.identities = new Map([[U1, ident(U1, 'u1@x.test', false)], [U2, ident(U2, 'u2@x.test', true)], [ME, ident(ME, 'me@x.test', false)]])
  h.groups = new Map([[U2, ['billing']]])
  h.facts = { billing: { declared: true, everyOrganisation: false, empty: false }, platform_ops: { declared: true, everyOrganisation: true, empty: false } }
  h.grants = []
  h.created = []
  h.sends = []
  h.drafts = []
  h.emits = []
  h.site = {
    name: 'payroll',
    gates: [{ id: 'web' }, { id: 'api' }],
    routes: { items: [{ id: 'home', methods: ['GET'], path: '/', gate: 'web', access: { kind: 'signed-in' }, source: 'manual' }, { id: 'locked', methods: ['GET'], path: '/locked', gate: 'web', access: { kind: 'deny' }, source: 'manual', pinned: true }], catchAll: { gate: 'web', access: { kind: 'deny' } } },
  }
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: { body?: string }) => {
    if (String(url).endsWith('/self-service/verification/api')) return new Response(JSON.stringify({ id: 'f', ui: { nodes: [{ group: 'link' }] } }), { status: 200 })
    if (init?.body) h.sends.push(JSON.parse(init.body).email)
    return new Response('{}', { status: 200 })
  }))
})

const post = (path: string, payload: object, headers: Record<string, string>) =>
  app.inject({ method: 'POST', url: `/api/admin/bulk/${path}`, payload, headers })
const VERIFY = { 'x-test-perms': 'users:verify,users:read' }

async function planAndRun(op: string, body: object, headers: Record<string, string>) {
  const plan = (await post(`${op}/plan`, body, headers)).json()
  const exec = await post(`${op}/execute`, { planId: plan.planId, planHash: plan.planHash }, headers)
  await settle()
  const job = (await app.inject({ url: `/api/admin/bulk/jobs/${plan.planId}`, headers })).json()
  return { plan, exec, job }
}

describe('route table', () => {
  it('declares each operation\'s permission on its plan and execute routes; the job is the caller\'s own', () => {
    const row = (m: string, p: string) => declaredRoutes().find((r) => r.method === m && r.path === `/api/admin/bulk/${p}`)
    for (const [op, perm] of [['sites.routes.upsert', 'sites:write'], ['users.invite', 'users:create'], ['users.verification', 'users:verify'], ['groups.members.add', 'groups.members:write']]) {
      expect(row('POST', `${op}/plan`)?.permission).toBe(perm)
      expect(row('POST', `${op}/execute`)?.permission).toBe(perm)
    }
    expect(row('POST', 'groups.members.add/execute')?.stepUp).toBe(true)
    expect(row('GET', 'jobs/:id')).toMatchObject({ class: 'authenticated', access: 'self' })
    expect(declaredRoutes().filter((r) => r.path.startsWith('/api/admin/bulk') && r.method === 'DELETE')).toEqual([])
  })
})

describe('plan', () => {
  it('judges each item: ok, skip, not_found (with users:read), self, duplicate, invalid', async () => {
    const res = await post('users.verification/plan', { items: [{ user: U1 }, { user: 'u2@x.test' }, { user: 'ghost@x.test' }, { user: ME }, { user: U1 }, { nope: 1 }] }, VERIFY)
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.items.map((i: { outcome: { status: string; reason?: string } }) => i.outcome.reason ?? i.outcome.status)).toEqual([
      'ok', 'already_verified', 'not_found', 'self_change', 'duplicate', expect.stringMatching(/^invalid:/),
    ])
    expect(body.counts).toEqual({ ok: 1, skip: 1, refused: 3, not_found: 1 })
    expect(body.planHash).toMatch(/^[a-f0-9]{64}$/)
    expect(h.sends).toEqual([])
  })

  it('says nothing about who exists to a caller without users:read', async () => {
    const res = await post('users.verification/plan', { items: [{ user: 'ghost@x.test' }] }, { 'x-test-perms': 'users:verify' })
    expect(res.json().items[0].outcome).toEqual({ status: 'refused', reason: 'unavailable' })
  })

  it('takes at most 200 items', async () => {
    const res = await post('users.verification/plan', { items: Array.from({ length: 201 }, (_, i) => ({ user: `u${i}@x.test` })) }, VERIFY)
    expect(res.statusCode).toBe(400)
  })

  it('needs the operation\'s permission', async () => {
    expect((await post('users.verification/plan', { items: [{ user: U1 }] }, { 'x-test-perms': 'users:read' })).statusCode).toBe(403)
  })
})

describe('execute', () => {
  it('runs the ok items, reports each item, and audits the job once plus each item', async () => {
    const { exec, job } = await planAndRun('users.verification', { items: [{ user: U1 }, { user: U2 }] }, VERIFY)
    expect(exec.statusCode).toBe(202)
    expect(job.state).toBe('done')
    expect(job.items).toEqual([{ index: 0, status: 'done', action: 'send' }, { index: 1, status: 'skipped', reason: 'already_verified' }])
    expect(job.counts).toMatchObject({ done: 1, skipped: 1, pending: 0 })
    expect(h.sends).toEqual(['u1@x.test'])
    expect(h.emits.filter((e) => e.v1Event === 'bulk.executed')).toHaveLength(1)
    const item = h.emits.find((e) => e.v1Event === 'user.verification_sent')!
    expect((item.details as { bulk: string }).bulk).toBe(job.id)
    expect(JSON.stringify(h.emits)).not.toContain('u1@x.test')
  })

  it('refuses a wrong hash, and a plan that is not the caller\'s', async () => {
    const plan = (await post('users.verification/plan', { items: [{ user: U1 }] }, VERIFY)).json()
    expect((await post('users.verification/execute', { planId: plan.planId, planHash: 'f'.repeat(64) }, VERIFY)).json().error).toBe('plan_hash_mismatch')
    expect((await post('users.verification/execute', { planId: plan.planId, planHash: plan.planHash }, { ...VERIFY, 'x-user': U2 })).statusCode).toBe(404)
    expect((await post('users.invite/execute', { planId: plan.planId, planHash: plan.planHash }, { 'x-test-perms': 'users:create' })).statusCode).toBe(404)
  })

  it('refuses a plan whose outcome changed since, and hands back the new plan', async () => {
    const plan = (await post('users.verification/plan', { items: [{ user: U1 }] }, VERIFY)).json()
    ;(h.identities.get(U1)!.verifiable_addresses as Array<{ verified: boolean }>)[0].verified = true
    const res = await post('users.verification/execute', { planId: plan.planId, planHash: plan.planHash }, VERIFY)
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toBe('plan_changed')
    expect(res.json().plan.items[0].outcome).toEqual({ status: 'skip', reason: 'already_verified' })
    expect(h.sends).toEqual([])
  })

  it('executing the same plan again answers its job and does nothing twice', async () => {
    const { plan } = await planAndRun('users.verification', { items: [{ user: U1 }] }, VERIFY)
    const again = await post('users.verification/execute', { planId: plan.planId, planHash: plan.planHash }, VERIFY)
    await settle()
    expect(again.statusCode).toBe(200)
    expect(again.json().state).toBe('done')
    expect(h.sends).toEqual(['u1@x.test'])
  })

  it('resumes a job whose runner stopped, running only the items not yet done', async () => {
    h.identities.set(U2, ident(U2, 'u2@x.test', false))
    const plan = (await post('users.verification/plan', { items: [{ user: U1 }, { user: U2 }] }, VERIFY)).json()
    // A runner that died after the first item: the job says running, its lease has lapsed.
    const now = new Date().toISOString()
    h.redis.set(`jinbe:bulk:job:${plan.planId}`, JSON.stringify({
      id: plan.planId, op: 'users.verification', owner: { id: ME, clientId: null }, planHash: plan.planHash, state: 'running', total: 2,
      items: [{ index: 0, status: 'done', action: 'send' }, { index: 1, status: 'pending' }], createdAt: now, updatedAt: now,
    }))
    const res = await post('users.verification/execute', { planId: plan.planId, planHash: plan.planHash }, VERIFY)
    await settle()
    expect(res.statusCode).toBe(202)
    expect(h.sends).toEqual(['u2@x.test'])
    const job = (await app.inject({ url: `/api/admin/bulk/jobs/${plan.planId}`, headers: VERIFY })).json()
    expect(job.counts).toMatchObject({ done: 2, pending: 0 })
  })

  it('re-checks each item right before it runs (a right lost since the plan is honoured)', async () => {
    const plan = (await post('users.invite/plan', { items: [{ email: 'a@x.test' }], params: { sendInvite: true } }, { 'x-test-perms': 'users:create,users:recovery' })).json()
    expect(plan.items[0].outcome.status).toBe('ok')
    // Executed by the same person after losing users:recovery: the re-plan differs → refused.
    const res = await post('users.invite/execute', { planId: plan.planId, planHash: plan.planHash }, { 'x-test-perms': 'users:create' })
    expect(res.statusCode).toBe(409)
    expect(h.created).toEqual([])
  })

  it('a job is only its owner\'s', async () => {
    const { plan } = await planAndRun('users.verification', { items: [{ user: U1 }] }, VERIFY)
    expect((await app.inject({ url: `/api/admin/bulk/jobs/${plan.planId}`, headers: { 'x-user': U2 } })).statusCode).toBe(404)
  })
})

describe('users.invite', () => {
  it('creates new users, skips existing ones, refuses the invite mail without users:recovery', async () => {
    const H = { 'x-test-perms': 'users:create,users:read' }
    const { plan, job } = await planAndRun('users.invite', { items: [{ email: 'New@X.test', name: 'New' }, { email: 'u1@x.test' }] }, H)
    expect(plan.items.map((i: { outcome: { status: string } }) => i.outcome.status)).toEqual(['ok', 'skip'])
    expect(job.items[0]).toEqual({ index: 0, status: 'done', action: 'create' })
    expect(h.created).toEqual([{ schema_id: 'default', state: 'active', traits: { email: 'new@x.test', name: 'New' } }])
    const refused = (await post('users.invite/plan', { items: [{ email: 'b@x.test' }], params: { sendInvite: true } }, H)).json()
    expect(refused.items[0].outcome).toEqual({ status: 'refused', reason: 'missing:users:recovery' })
  })
})

describe('groups.members.add', () => {
  const G = { 'x-test-perms': 'groups.members:write,users:read', 'x-test-mfa': '1' }

  it('adds only (add-only mode of the grant gate), skips members, refuses unknown groups and the caller', async () => {
    const { plan, job } = await planAndRun('groups.members.add', {
      items: [{ user: U1, groups: ['billing'] }, { user: U2, groups: ['billing'] }, { user: 'u1@x.test', groups: ['nope'] }, { user: ME, groups: ['billing'] }],
    }, G)
    expect(plan.items.map((i: { outcome: { status: string; reason?: string } }) => i.outcome.reason ?? i.outcome.status)).toEqual([
      'ok', 'already_member', 'group_not_in_model:nope', 'self_change',
    ])
    expect(job.items[0]).toMatchObject({ status: 'done' })
    expect(h.grants).toHaveLength(1)
    expect(h.grants[0]).toMatchObject({ addGroups: ['billing'], newGroups: [], privilegePolicy: { kind: 'super_admin_required' }, auditExtraDetails: { bulk: job.id } })
  })

  it('needs a recent second factor (the catalogue step-up on groups.members:write)', async () => {
    expect((await post('groups.members.add/plan', { items: [{ user: U1, groups: ['billing'] }] }, { 'x-test-perms': 'groups.members:write' })).statusCode).toBe(422)
  })
})

describe('sites.routes.upsert', () => {
  const S = { 'x-test-perms': 'sites:write' }
  const route = (id: string, extra: Record<string, unknown> = {}) => ({ id, methods: ['GET'], path: `/${id}`, gate: 'api', access: { kind: 'permission', permission: 'payroll:read' }, ...extra })

  it('maps routes on the draft in one write: create, update, unchanged, pinned, unknown gate, clash — never applies', async () => {
    const { plan, job } = await planAndRun('sites.routes.upsert', {
      params: { site: 'payroll' },
      items: [
        route('reports'),
        { id: 'home', methods: ['GET'], path: '/', gate: 'web', access: { kind: 'public' } },
        { id: 'home', methods: ['GET'], path: '/', gate: 'web', access: { kind: 'signed-in' } },
        route('locked'),
        route('x', { gate: 'nope' }),
        route('dup', { path: '/' }),
      ],
    }, S)
    expect(plan.items.map((i: { outcome: { status: string; reason?: string; action?: string } }) => i.outcome.action ?? i.outcome.reason)).toEqual([
      'create', 'update', 'duplicate', 'pinned', 'unknown_gate:nope', 'same_route_as:home',
    ])
    expect(job.counts).toMatchObject({ done: 2, refused: 4 })
    expect(h.drafts).toHaveLength(1)
    const items = (h.drafts[0].site.routes as { items: Array<{ id: string; access: { kind: string } }> }).items
    expect(items.map((r) => r.id)).toEqual(['home', 'locked', 'reports'])
    expect(items[0].access.kind).toBe('public')
  })

  it('refuses a system site and an unknown one', async () => {
    expect((await post('sites.routes.upsert/plan', { params: { site: 'kuma' }, items: [route('a')] }, S)).statusCode).toBe(403)
    h.site = null
    expect((await post('sites.routes.upsert/plan', { params: { site: 'payroll' }, items: [route('a')] }, S)).statusCode).toBe(404)
  })
})

describe('through an MCP key (delegated)', () => {
  it('checks the key\'s scope per operation, from the route the op declares', async () => {
    const res = await post('users.verification/plan', { items: [{ user: U1 }] }, { ...VERIFY, 'x-scopes': 'users:read' })
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ code: 'insufficient_scope', reason: 'scope_missing:users:verify' })
    const { job } = await planAndRun('users.verification', { items: [{ user: U1 }] }, { ...VERIFY, 'x-scopes': 'users:verify' })
    expect(job.state).toBe('done')
  })

  it('refuses a platform-wide group for a key without its creation-time second factor', async () => {
    const res = await post('groups.members.add/plan', { items: [{ user: U1, groups: ['platform_ops'] }] }, { 'x-test-perms': 'groups.members:write', 'x-test-mfa': '1', 'x-scopes': 'groups.members:write' })
    expect(res.json().items[0].outcome).toEqual({ status: 'refused', reason: 'step_up_unavailable:platform_ops' })
  })

  it('adds a platform-wide group for a key carrying its creation-time second factor (stepUpViaKey, as the group controllers)', async () => {
    // x-test-mfa: the route's step-up stand-in (the real guard's key proof is sites-delegated.test.ts).
    const K = { 'x-test-perms': 'groups.members:write', 'x-test-mfa': '1', 'x-scopes': 'groups.members:write', 'x-key-step-up': new Date(Date.now() - 3600_000).toISOString() }
    const { plan, job } = await planAndRun('groups.members.add', { items: [{ user: U1, groups: ['platform_ops'] }] }, K)
    expect(plan.items[0].outcome.status).toBe('ok')
    expect(job.items[0]).toMatchObject({ status: 'done' })
    expect(h.grants[0]).toMatchObject({ addGroups: ['platform_ops'], actor: expect.objectContaining({ stepUpViaKey: true, authVia: 'delegated' }) })
  })

  it('does not report unknown users to a key whose scopes lack users:read, whatever the user holds', async () => {
    const res = await post('users.verification/plan', { items: [{ user: 'ghost@x.test' }] }, { ...VERIFY, 'x-scopes': 'users:verify' })
    expect(res.json().items[0].outcome).toEqual({ status: 'refused', reason: 'unavailable' })
  })
})
