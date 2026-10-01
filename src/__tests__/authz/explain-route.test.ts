import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// POST /api/admin/rbac/explain-route: the route's REAL guards run in a dry run against the subject,
// beside OPA's decision with the guard's exact input and rbac.explain. OPA is mocked at the HTTP
// boundary only (as in opa-guards.test.ts); what jinbe sends is asserted, what OPA answers is obeyed.

const s = vi.hoisted(() => ({
  calls: [] as Array<{ rule: string; input: Record<string, unknown> }>,
  explainLoaded: true,
  // What each person holds per org, as OPA answers rbac.org_permissions_by_org (owner of Acme).
  inOrg: { 'acme-admin': { acme: ['org.members:read', 'org.members:write'] } } as Record<string, Record<string, string[]>>,
  identities: {} as Record<string, { id: string; traits: { email: string } }>,
  siteStepUp: false,
}))

vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  const over: Record<string, unknown> = { OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret', DEV_BYPASS_AUTH: false }
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in over ? over[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../config/index.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/index.js')>()
  const over: Record<string, unknown> = { OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret', DEV_BYPASS_AUTH: false }
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in over ? over[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getRouteMap: vi.fn(async () => ({ rules: [{ method: 'GET', path: '/api/organizations/:organizationId/users', permission: 'org.members:read' }] })),
    getOrgSites: vi.fn(async () => ({ acme: ['payroll'] })),
    getGroups: vi.fn(async () => ({})),
  },
}))
vi.mock('../../services/org-roles.repository.js', () => ({ orgRolesRepository: { getForMember: vi.fn(async (_o: string, id: string) => (id === 'id-acme-admin' ? ['jinbe:owner'] : [])) } }))
vi.mock('../../services/kratos.service.js', () => ({
  kratosService: {
    findByEmail: vi.fn(async (email: string) => Object.values(s.identities).find((i) => i.traits.email === email) ?? null),
    getIdentity: vi.fn(async (id: string) => {
      const found = s.identities[id]
      if (!found) throw Object.assign(new Error('not found'), { statusCode: 404 })
      return found
    }),
  },
}))
const emitted = vi.hoisted(() => vi.fn(async () => 'id'))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: emitted } }))
const checked = vi.hoisted(() => vi.fn())
vi.mock('../../audit/record.js', async (importOriginal) => ({ ...(await importOriginal<object>()), auditAccessCheck: checked }))
const budget = vi.hoisted(() => vi.fn(async () => null))
vi.mock('../../middleware/delegated-writes.js', async (importOriginal) => ({ ...(await importOriginal<object>()), delegatedWriteBudget: budget }))

const JINBE: Record<string, string[]> = { super: ['stats:read', 'access:check'], auditor: ['access:check'], 'acme-admin': [], nobody: [] }
const who = (email: unknown) => String(email).split('@')[0]

function decision(input: Record<string, unknown>) {
  const u = who(input.email)
  const org = String(input.object).split('/')[3]
  const inOrg = (s.inOrg[u]?.[org] ?? []).length > 0
  const granted = u === 'super' || inOrg
  // Platform 2FA (8c) for super, per-site 2FA (8b) for everybody at aal1 when the site asks.
  const platform = granted && u === 'super' && input.client !== true && input.aal !== 'aal2'
  const site = granted && s.siteStepUp && input.client !== true && input.aal === 'aal1'
  const stepUp = platform || site
  return {
    allow: granted && !stepUp,
    reason: stepUp ? 'needs_2fa' : granted ? 'ok' : String(input.object).includes('/nowhere') ? 'not_found' : 'forbidden',
    grantedBy: u === 'super' ? ['every_org'] : inOrg ? ['org_role'] : [],
    stepUpBy: [...(site ? ['site_8b'] : []), ...(platform ? ['platform_8c'] : [])],
  }
}

function answer(rule: string, input: Record<string, unknown>): unknown {
  switch (rule) {
    case 'rbac/user_info':
      return { groups: [], roles: [], permissions: JINBE[who(input.email)] ?? [] }
    case 'rbac/org_permissions_by_org':
      return who(input.email) === 'super' ? { acme: ['org.members:read', 'org.members:write'] } : s.inOrg[who(input.email)] ?? {}
    case 'rbac/caller_organizations':
      return who(input.email) === 'acme-admin' ? ['acme'] : []
    case 'rbac/second_factor_required':
      return who(input.email) === 'super'
    case 'rbac/simulate':
      return { matching_rules: [{ method: 'GET', path: '/api/organizations/:organizationId/users', permission: 'org.members:read' }] }
    case 'rbac/decision': {
      const d = decision(input)
      return { allow: d.allow, reason: d.reason, groups: [] }
    }
    case 'rbac/explain': {
      if (!s.explainLoaded) return undefined
      const d = decision(input)
      return {
        allow: d.allow, reason: d.reason, granted: d.grantedBy.length > 0, granted_by: d.grantedBy, step_up_required: d.stepUpBy.length > 0,
        step_up_by: d.stepUpBy, effective_app: 'jinbe', is_client: input.client === true, session_aal: 0, second_factor_required: who(input.email) === 'super',
        matching_rules: [{ method: 'GET', path: '/api/organizations/:organizationId/users', permission: 'org.members:read' }],
      }
    }
  }
  return undefined
}

import { installRouteAccess, needs } from '../../policy/route-access.js'
import { delegationGate } from '../../middleware/delegation-gate.js'
import { explainRouteRoutes } from '../../routes/explain-route.routes.js'
import { clearAuthzCache } from '../../authz/opa.js'

let app: FastifyInstance
let handled = 0
beforeAll(async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string | URL, init?: RequestInit) => {
    const rule = String(url).replace('http://opal-client:8181/v1/data/', '')
    const body = JSON.parse(String(init?.body ?? '{}')) as { input: Record<string, unknown> }
    s.calls.push({ rule, input: body.input })
    return Response.json({ result: answer(rule, body.input) })
  }))
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    const u = request.headers['x-test-user'] as string | undefined
    if (!u) return
    const scopes = request.headers['x-test-scopes'] as string | undefined
    request.userContext = scopes !== undefined
      ? { id: `id-${u}`, email: `${u}@example.com`, name: u, authVia: 'delegated', delegation: { clientId: 'claude', scopes: scopes.split(' ').filter(Boolean), kind: 'oauth', via: 'auth-mcp' } } as never
      : { id: `id-${u}`, email: `${u}@example.com`, name: u, aal: (request.headers['x-test-aal'] as string | undefined) ?? 'aal2', authVia: 'session' } as never
  })
  app.addHook('preHandler', delegationGate)
  const handler = async () => {
    handled++
    return { ok: true }
  }
  await app.register(async (api) => {
    await api.register(async (org) => {
      org.get('/users', needs('org.members:read', { org: 'organizationId' }), handler)
      org.post('/users', needs('org.members:write', { org: 'organizationId' }), handler)
    }, { prefix: '/organizations/:organizationId' })
    api.get('/admin/stats', needs('stats:read'), handler)
    await api.register(explainRouteRoutes, { prefix: '/admin/rbac' })
  }, { prefix: '/api' })
  await app.ready()
})
afterAll(async () => {
  await app.close()
  vi.unstubAllGlobals()
})
beforeEach(() => {
  s.calls.length = 0
  s.explainLoaded = true
  s.inOrg = { 'acme-admin': { acme: ['org.members:read', 'org.members:write'] } }
  s.siteStepUp = false
  s.identities = { 'id-acme-admin': { id: 'id-acme-admin', traits: { email: 'acme-admin@example.com' } } }
  handled = 0
  emitted.mockClear()
  checked.mockClear()
  budget.mockClear()
  clearAuthzCache()
})

type Step = { step: string; verdict: string; input?: Record<string, unknown>; detail: Record<string, unknown> }
const explain = async (body: Record<string, unknown>, headers: Record<string, string>) => {
  const res = await app.inject({ method: 'POST', url: '/api/admin/rbac/explain-route', payload: body, headers })
  const json = res.json()
  return { res, json, step: (name: string) => (json.steps as Step[]).find((x) => x.step === name)! }
}

describe('explain-route — the caller as they are calling', () => {
  it('a delegated super admin (MCP list_org_users): client to OPA, granted by the every-org map, reaches the handler', async () => {
    const { res, json, step } = await explain({ method: 'get', path: '/api/organizations/acme/users' }, { 'x-test-user': 'super', 'x-test-scopes': 'org.members:read' })
    expect(res.statusCode).toBe(200)
    expect(json.verdict).toEqual({ status: 200, allowed: true })
    expect(json.decidedBy).toBe('handler')
    expect(json.subject).toMatchObject({ email: 'super@example.com', via: 'delegated', client: true })
    expect(step('route').detail).toMatchObject({ pattern: '/api/organizations/:organizationId/users', permission: 'org.members:read', org: 'organizationId' })
    expect(step('route').detail.guards).toEqual(expect.arrayContaining(['delegationGate', 'requireOrgPermission']))
    expect(step('delegation')).toMatchObject({ verdict: 'pass' })
    // Exactly the guard's input: client, delegated, the token's scopes.
    expect(step('opa').input).toMatchObject({ email: 'super@example.com', object: '/api/organizations/acme/users', action: 'GET', app: 'jinbe', client: true, delegated: true, scopes: ['org.members:read'] })
    expect(step('opa').detail).toMatchObject({ allow: true, reason: 'ok', explain: { available: true, grantedBy: ['every_org'] } })
    expect(json.disagreements).toEqual([])
    // A dry run: the handler never ran.
    expect(handled).toBe(0)
  })

  it('an org owner at aal1 on a site asking 2FA is refused needs_2fa by the org gate, clause named — nothing audited as denied', async () => {
    s.siteStepUp = true
    const { json, step } = await explain({ method: 'GET', path: '/api/organizations/acme/users' }, { 'x-test-user': 'acme-admin', 'x-test-aal': 'aal1' })
    expect(json.verdict).toMatchObject({ status: 403, allowed: false, code: 'needs_2fa', reason: 'needs_2fa' })
    expect(json.decidedBy).toBe('requireOrgPermission')
    expect(step('opa').input).toMatchObject({ client: false, aal: 'aal1' })
    expect(step('opa').detail).toMatchObject({ reason: 'needs_2fa', explain: { grantedBy: ['org_role'], stepUpBy: ['site_8b'] } })
    expect(step('guard').detail.guards).toEqual(expect.arrayContaining([expect.objectContaining({ guard: 'requireOrgPermission', verdict: 'refuse', status: 403 })]))
    expect(json.disagreements).toEqual([])
    expect(emitted).not.toHaveBeenCalled()
  })

  it('a super admin at aal1: OPA refuses needs_2fa and so does jinbe — one rule, no platform bypass', async () => {
    const { json, step } = await explain({ method: 'GET', path: '/api/organizations/acme/users' }, { 'x-test-user': 'super', 'x-test-aal': 'aal1' })
    expect(step('opa').detail).toMatchObject({ allow: false, reason: 'needs_2fa', explain: { stepUpBy: ['platform_8c'] } })
    expect(step('org').detail).toMatchObject({ org: 'acme', holdsRoutePermissionHere: true })
    expect(json.verdict).toMatchObject({ status: 403, allowed: false, code: 'needs_2fa' })
    expect(json.disagreements).toEqual([])
  })

  it('without rbac.explain in the policy it degrades: the clause is inferred where it can be, every other step still runs', async () => {
    s.explainLoaded = false
    const { res, json, step } = await explain({ method: 'GET', path: '/api/organizations/acme/users', aal: 'aal1', via: 'session' }, { 'x-test-user': 'super' })
    expect(res.statusCode).toBe(200)
    expect(step('opa').detail.explain).toMatchObject({ available: false, stepUpByInferred: ['platform_8c'] })
    expect(json.steps).toHaveLength(7)
    expect(json.decidedBy).toBe('requireOrgPermission')
  })

  it('an unknown path is a 404 verdict decided by the route step', async () => {
    const { json } = await explain({ method: 'GET', path: '/api/nowhere/at/all' }, { 'x-test-user': 'super' })
    expect(json.verdict).toMatchObject({ status: 404, allowed: false })
    expect(json.decidedBy).toBe('route')
  })

  it('a delegated write in a dry run spends none of the write budget', async () => {
    await explain({ method: 'POST', path: '/api/organizations/acme/users' }, { 'x-test-user': 'super', 'x-test-scopes': 'org.members:write' })
    expect(budget).not.toHaveBeenCalled()
  })

  it('a delegated caller asking about a route its token does not cover sees the delegation gate refuse', async () => {
    const { json, step } = await explain({ method: 'GET', path: '/api/admin/stats' }, { 'x-test-user': 'super', 'x-test-scopes': 'org.members:read' })
    expect(step('delegation')).toMatchObject({ verdict: 'refuse', detail: { reason: 'scope_missing:stats:read' } })
    expect(json.decidedBy).toBe('delegationGate')
    expect(json.verdict).toMatchObject({ status: 403, code: 'insufficient_scope' })
  })

  it('bad input is a 400', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/admin/rbac/explain-route', payload: { method: 'GET', path: 'no-slash' }, headers: { 'x-test-user': 'super' } })
    expect(res.statusCode).toBe(400)
  })
})

describe('explain-route — the org step', () => {
  it('shows membership, the org roles assigned there, the org permissions held there and the entitled sites', async () => {
    const { json, step } = await explain({ method: 'GET', path: '/api/organizations/acme/users' }, { 'x-test-user': 'acme-admin' })
    expect(json.verdict).toMatchObject({ status: 200, allowed: true })
    expect(step('org').detail).toEqual({
      org: 'acme', member: true, roles: ['jinbe:owner'], permissions: ['org.members:read', 'org.members:write'],
      holdsRoutePermissionHere: true, sites: ['jinbe', 'payroll'],
    })
  })

  it('somebody holding nothing in the org is refused, with the permission and who grants it', async () => {
    const { json, step } = await explain({ method: 'GET', path: '/api/organizations/acme/users' }, { 'x-test-user': 'nobody' })
    expect(json.verdict).toMatchObject({ status: 403, code: 'permission_required', reason: 'forbidden' })
    expect(step('org').detail).toMatchObject({ member: false, permissions: [], holdsRoutePermissionHere: false })
  })
})

describe('explain-route — about somebody else', () => {
  it('needs access:check', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/admin/rbac/explain-route', payload: { method: 'GET', path: '/api/organizations/acme/users', subject: 'acme-admin@example.com' }, headers: { 'x-test-user': 'nobody' } })
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ code: 'permission_required', permission: 'access:check' })
  })

  it('with access:check: explained for the subject (judged as a session at aal2 unless told) and recorded', async () => {
    const { res, json } = await explain({ method: 'GET', path: '/api/organizations/acme/users', subject: 'acme-admin@example.com' }, { 'x-test-user': 'auditor' })
    expect(res.statusCode).toBe(200)
    expect(json.subject).toMatchObject({ id: 'id-acme-admin', email: 'acme-admin@example.com', via: 'session', aal: 'aal2' })
    expect(json.verdict).toMatchObject({ status: 200, allowed: true })
    expect(checked).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ email: 'acme-admin@example.com', path: '/api/organizations/acme/users' }), expect.objectContaining({ allow: true }))
  })

  it('by identity id too; an unknown subject is a 404', async () => {
    expect((await explain({ method: 'GET', path: '/api/organizations/acme/users', subject: 'id-acme-admin' }, { 'x-test-user': 'auditor' })).res.statusCode).toBe(200)
    expect((await explain({ method: 'GET', path: '/api/organizations/acme/users', subject: 'id-ghost' }, { 'x-test-user': 'auditor' })).res.statusCode).toBe(404)
  })

  it('asking about oneself never needs access:check and is not recorded', async () => {
    const { res } = await explain({ method: 'GET', path: '/api/organizations/acme/users', subject: 'nobody@example.com' }, { 'x-test-user': 'nobody' })
    expect(res.statusCode).toBe(200)
    expect(checked).not.toHaveBeenCalled()
  })
})
