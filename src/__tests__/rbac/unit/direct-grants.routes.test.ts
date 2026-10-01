import { describe, it, expect, beforeEach, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// Per-person direct grants: a role or a permission held without a group, platform-wide or in one org,
// reason and expiry optional, every change decided by the policy (rbac.delegation grant_direct /
// revoke_direct), audited, and stored by identity id.

const ORG = '7b0c6f3e-6c1a-4c55-9a43-2f6e1c0d9a11'
const OTHER_ORG = '8c1d7f4f-7d2b-4d66-8b54-3f7f2d1e0b22'
const ANN = '0f8b1a52-1111-4c55-9a43-2f6e1c0d9a11'
const BOB = '0f8b1a52-2222-4c55-9a43-2f6e1c0d9a11'

const s = vi.hoisted(() => ({ hash: new Map<string, string>(), emitted: [] as Array<Record<string, unknown>>, notified: 0 }))

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    hget: async (_k: string, f: string) => s.hash.get(f) ?? null,
    hgetall: async () => Object.fromEntries(s.hash),
    hset: async (_k: string, f: string, v: string) => { s.hash.set(f, v); return 1 },
    hdel: async (_k: string, f: string) => (s.hash.delete(f) ? 1 : 0),
  }),
}))
vi.mock('../../../services/redis-lock.js', () => ({ withRedisLock: async (_n: string, fn: () => Promise<unknown>) => fn() }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async (e: Record<string, unknown>) => { s.emitted.push(e) }) } }))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { notifyBindingsChanged: vi.fn(async () => { s.notified++ }) } }))
const twoFa = vi.hoisted(() => ({ enrolled: new Set<string>(), required: ['super_admins', 'staff-security'] }))
vi.mock('../../../second-factor/settings.js', () => ({ getSecondFactorGroups: vi.fn(async () => twoFa.required) }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { getGroups: vi.fn(async () => ({ 'staff-security': { jinbe: ['security'] }, 'staff-viewers': { jinbe: ['viewer'] } })) },
}))
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    hasMFA: vi.fn(async (id: string) => twoFa.enrolled.has(id)),
    getIdentity: vi.fn(async (id: string) => {
      if (id === ANN) return { id, organization_id: ORG, metadata_admin: {}, traits: { email: 'ann@acme.io' } }
      if (id === BOB) return { id, organization_id: null, metadata_admin: {}, traits: { email: 'bob@acme.io' } }
      throw new Error('404')
    }),
    getIdentitiesByIds: vi.fn(async (ids: string[]) => new Map(ids.map((id) => [id, { id, traits: { email: id === ANN ? 'ann@acme.io' : 'bob@acme.io' } }]))),
  },
}))

const { installRouteAccess } = await import('../../../policy/route-access.js')
const { adminDirectGrantsRoutes, orgDirectGrantsRoutes } = await import('../../../routes/direct-grants.routes.js')
const { opaWorld, refused, resetOpaWorld } = await import('../../helpers/opa-authz-mock.js')
const { grantVerdict } = await import('../../../authz/opa.js')
const { directGrantsService } = await import('../../../services/direct-grants.service.js')
const { errorHandler } = await import('../../../middleware/error-handler.js')

let app: FastifyInstance
let as = 'root@example.com'

beforeEach(async () => {
  vi.clearAllMocks()
  resetOpaWorld()
  s.hash.clear()
  s.emitted = []
  s.notified = 0
  as = 'root@example.com'
  opaWorld.permissions['root@example.com'] = ['users.grants:read', 'users.grants:write']
  opaWorld.permissions['reader@example.com'] = ['users.grants:read']
  opaWorld.orgPermissions['owner@acme.io'] = { [ORG]: ['org.members:read', 'org.members:write'] }
  opaWorld.decide = (q) => (opaWorld.orgPermissions[q.email]?.[ORG] ?? []).length > 0
  app = Fastify()
  installRouteAccess(app as never)
  app.setErrorHandler(errorHandler)
  app.addHook('onRequest', async (request) => {
    ;(request as unknown as { userContext: object }).userContext = { id: 'u1', email: as, aal: 'aal2', secondFactorAt: new Date().toISOString(), authVia: 'session' }
  })
  await app.register(async (api) => {
    await api.register(adminDirectGrantsRoutes, { prefix: '/admin' })
    await api.register(orgDirectGrantsRoutes, { prefix: '/organizations/:organizationId' })
  }, { prefix: '/api' })
  await app.ready()
})

const put = (url: string, grants: unknown[]) => app.inject({ method: 'PUT', url, payload: { grants } })

describe('platform side', () => {
  it('gives a role and a permission, with an optional reason and expiry; asks the policy for each; audits; publishes', async () => {
    const res = await put(`/api/admin/users/${ANN}/grants`, [
      { scope: 'platform', app: 'payroll', kind: 'role', name: 'editor', reason: 'covering for Bob', expiresAt: '2999-01-01T00:00:00.000Z' },
      { scope: 'platform', app: 'jinbe', kind: 'permission', name: 'users:read' },
    ])
    expect(res.statusCode).toBe(200)
    const grants = res.json().grants as Array<Record<string, unknown>>
    expect(grants.map((g) => [g.app, g.kind, g.name, g.reason ?? null, g.active])).toEqual([
      ['jinbe', 'permission', 'users:read', null, true],
      ['payroll', 'role', 'editor', 'covering for Bob', true],
    ])
    expect(grants[0]).toMatchObject({ grantedBy: 'root@example.com', grantedAt: expect.any(String), id: expect.any(String) })
    expect(grantVerdict).toHaveBeenCalledWith({ kind: 'grant_direct', actor: 'root@example.com', grantee: 'ann@acme.io', scope: 'platform', app: 'payroll', grantKind: 'role', name: 'editor' })
    expect(s.emitted.filter((e) => e.type === 'user.grant_granted')).toHaveLength(2)
    expect(s.notified).toBe(1)
  })

  it('re-sending the same grants asks nothing and changes nothing; dropping one asks revoke for its scope', async () => {
    const g = { scope: 'platform', app: 'jinbe', kind: 'permission', name: 'users:read' }
    await put(`/api/admin/users/${ANN}/grants`, [g])
    vi.mocked(grantVerdict).mockClear()
    s.notified = 0
    expect((await put(`/api/admin/users/${ANN}/grants`, [g])).statusCode).toBe(200)
    expect(grantVerdict).not.toHaveBeenCalled()
    expect(s.notified).toBe(0)
    expect((await put(`/api/admin/users/${ANN}/grants`, [])).json().grants).toEqual([])
    expect(grantVerdict).toHaveBeenCalledWith({ kind: 'revoke_direct', actor: 'root@example.com', scope: 'platform' })
    expect(s.emitted.map((e) => e.type)).toContain('user.grant_revoked')
  })

  it('a refused grant writes nothing and lists the refusal: reasons, what is missing, who could', async () => {
    opaWorld.verdict = (q) => (q.kind === 'grant_direct' && q.name === 'admin'
      ? refused({ reasons: ['missing_permissions'], missing: { payroll: ['payroll:delete'] }, missingEveryOrg: { jinbe: ['org.members:write'] }, grantedBy: ['payroll-admins', 'super_admins'] })
      : null)
    const res = await put(`/api/admin/users/${ANN}/grants`, [
      { scope: 'platform', app: 'payroll', kind: 'role', name: 'viewer' },
      { scope: 'platform', app: 'payroll', kind: 'role', name: 'admin' },
    ])
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({
      code: 'grant_exceeds_own',
      refused: [{ grant: { scope: 'platform', app: 'payroll', kind: 'role', name: 'admin' }, reasons: ['missing_permissions'], missing: ['payroll:delete', 'every organisation: org.members:write'], grantedBy: ['payroll-admins', 'super_admins'] }],
    })
    expect(s.hash.size).toBe(0)
    expect(s.emitted.map((e) => e.type)).toEqual(['user.grant_refused'])
  })

  it('refuses a wildcard, an unknown kind and a past expiry (400); 404 for nobody; 503 when OPA cannot tell', async () => {
    expect((await put(`/api/admin/users/${ANN}/grants`, [{ scope: 'platform', app: 'payroll', kind: 'permission', name: 'payroll:*' }])).statusCode).toBe(400)
    expect((await put(`/api/admin/users/${ANN}/grants`, [{ scope: 'platform', app: 'payroll', kind: 'group', name: 'x' }])).statusCode).toBe(400)
    expect((await put(`/api/admin/users/${ANN}/grants`, [{ scope: 'platform', app: 'payroll', kind: 'role', name: 'x', expiresAt: '2020-01-01T00:00:00Z' }])).statusCode).toBe(400)
    expect((await put('/api/admin/users/0f8b1a52-9999-4c55-9a43-2f6e1c0d9a11/grants', [])).statusCode).toBe(404)
    opaWorld.down = true
    expect((await put(`/api/admin/users/${ANN}/grants`, [{ scope: 'platform', app: 'payroll', kind: 'role', name: 'x' }])).statusCode).toBe(503)
    expect(s.hash.size).toBe(0)
  })

  it('reads one person, and lists everyone holding direct grants (review); revokes one by id', async () => {
    await put(`/api/admin/users/${ANN}/grants`, [{ scope: 'platform', app: 'jinbe', kind: 'permission', name: 'users:read' }])
    await put(`/api/admin/users/${BOB}/grants`, [{ scope: 'platform', app: 'payroll', kind: 'role', name: 'viewer' }])
    as = 'reader@example.com'
    const all = (await app.inject({ url: '/api/admin/grants' })).json().people as Array<{ email: string; grants: unknown[] }>
    expect(all.map((p) => p.email)).toEqual(['ann@acme.io', 'bob@acme.io'])
    const ann = (await app.inject({ url: `/api/admin/users/${ANN}/grants` })).json()
    expect(ann.email).toBe('ann@acme.io')
    // A reader may not change anything.
    expect((await app.inject({ method: 'DELETE', url: `/api/admin/users/${ANN}/grants/${ann.grants[0].id}` })).statusCode).toBe(403)
    as = 'root@example.com'
    const gone = await app.inject({ method: 'DELETE', url: `/api/admin/users/${ANN}/grants/${ann.grants[0].id}` })
    expect(gone.statusCode).toBe(200)
    expect(gone.json().grants).toEqual([])
    expect((await app.inject({ method: 'DELETE', url: `/api/admin/users/${ANN}/grants/${ann.grants[0].id}` })).statusCode).toBe(404)
  })
})

describe('jinbe-side rules', () => {
  it('super_admin is never given directly: 403 never_direct, before the policy is asked', async () => {
    const res = await put(`/api/admin/users/${ANN}/grants`, [{ scope: 'platform', app: 'jinbe', kind: 'role', name: 'super_admin' }])
    expect(res.statusCode).toBe(403)
    expect(res.json().refused).toEqual([{ grant: { scope: 'platform', app: 'jinbe', kind: 'role', name: 'super_admin' }, reasons: ['never_direct'], missing: [], grantedBy: ['super_admins'] }])
    expect(grantVerdict).not.toHaveBeenCalled()
    expect(s.emitted).toContainEqual(expect.objectContaining({ type: 'user.grant_refused', result: 'denied' }))
  })

  it('a role a 2FA-required group binds needs the person enrolled first (mfa_required, 422); a role no such group binds does not', async () => {
    const res = await put(`/api/admin/users/${ANN}/grants`, [{ scope: 'platform', app: 'jinbe', kind: 'role', name: 'security' }])
    expect(res.statusCode).toBe(422)
    expect(res.json()).toMatchObject({ error: 'mfa_required', targetEmail: 'ann@acme.io', targetGroups: ['staff-security'], secondFactor: { rule: 'enrol_before_joining' } })
    expect(s.hash.size).toBe(0)
    expect(s.emitted).toContainEqual(expect.objectContaining({ type: 'user.grant_refused', result: 'denied', details: expect.objectContaining({ reason: 'mfa_required', role: 'jinbe:security' }) }))
    expect((await put(`/api/admin/users/${ANN}/grants`, [{ scope: 'platform', app: 'jinbe', kind: 'role', name: 'viewer' }])).statusCode).toBe(200)
    twoFa.enrolled.add(ANN)
    expect((await put(`/api/admin/users/${ANN}/grants`, [{ scope: 'platform', app: 'jinbe', kind: 'role', name: 'security' }])).statusCode).toBe(200)
    twoFa.enrolled.clear()
  })
})

describe('org side', () => {
  it("an org member's grants in this org only: scope must be this org; other scopes untouched", async () => {
    await put(`/api/admin/users/${ANN}/grants`, [{ scope: 'platform', app: 'jinbe', kind: 'permission', name: 'users:read' }])
    as = 'owner@acme.io'
    const res = await put(`/api/organizations/${ORG}/users/${ANN}/grants`, [{ scope: ORG, app: 'jinbe', kind: 'role', name: 'viewer' }])
    expect(res.statusCode).toBe(200)
    expect(res.json().grants.map((g: { scope: string; name: string }) => [g.scope, g.name])).toEqual([[ORG, 'viewer']])
    expect(grantVerdict).toHaveBeenCalledWith(expect.objectContaining({ kind: 'grant_direct', actor: 'owner@acme.io', scope: ORG, grantee: 'ann@acme.io' }))
    // The platform grant is still there.
    as = 'root@example.com'
    expect((await app.inject({ url: `/api/admin/users/${ANN}/grants` })).json().grants).toHaveLength(2)
    as = 'owner@acme.io'
    expect((await put(`/api/organizations/${ORG}/users/${ANN}/grants`, [{ scope: OTHER_ORG, app: 'jinbe', kind: 'role', name: 'viewer' }])).statusCode).toBe(400)
    expect((await put(`/api/organizations/${ORG}/users/${ANN}/grants`, [{ scope: 'platform', app: 'jinbe', kind: 'role', name: 'viewer' }])).statusCode).toBe(400)
  })

  it('404 for somebody who is not a member; the org gate refuses a caller holding nothing there', async () => {
    as = 'owner@acme.io'
    expect((await app.inject({ url: `/api/organizations/${ORG}/users/${BOB}/grants` })).statusCode).toBe(404)
    as = 'nobody@x.io'
    expect((await app.inject({ url: `/api/organizations/${ORG}/users/${ANN}/grants` })).statusCode).toBe(403)
  })
})

describe('expiry', () => {
  it('the sweep takes expired grants out, audits each, and republishes', async () => {
    s.hash.set(ANN, JSON.stringify([
      { id: 'g1', scope: 'platform', app: 'jinbe', kind: 'permission', name: 'users:read', expiresAt: '2020-01-01T00:00:00.000Z', grantedBy: 'root@example.com', grantedAt: '2019-01-01T00:00:00.000Z' },
      { id: 'g2', scope: 'platform', app: 'jinbe', kind: 'permission', name: 'sessions:read', grantedBy: 'root@example.com', grantedAt: '2019-01-01T00:00:00.000Z' },
    ]))
    expect(await directGrantsService.sweep()).toBe(1)
    expect(JSON.parse(s.hash.get(ANN)!).map((g: { id: string }) => g.id)).toEqual(['g2'])
    expect(s.emitted).toEqual([expect.objectContaining({ type: 'user.grant_expired', target: { type: 'user', id: ANN } })])
    expect(s.notified).toBe(1)
    expect(await directGrantsService.sweep()).toBe(0)
  })
})
