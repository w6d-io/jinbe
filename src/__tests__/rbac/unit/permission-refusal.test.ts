import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// Every 403 for a missing permission says what to do about it, machine-readably: the permission (or
// what is missing), the groups whose roles grant it — staff groups included, never their members —
// and who to ask. kuma and auth-mcp render `grantedBy` and `hint`. The existing error / code stay.

const h = vi.hoisted(() => ({ held: [] as string[] }))

vi.mock('../../../authz/opa.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../authz/opa.js')>()),
  rights: vi.fn(async () => ({ groups: [], roles: [], permissions: h.held })),
  // The policy's verdict on the group definition below (rbac.delegation.define_group_verdict).
  grantVerdict: vi.fn(async () => ({
    allow: false,
    reasons: ['missing_every_org_permissions', 'missing_permissions'],
    missing: { jinbe: ['users:disable', 'users:reset_second_factor'] },
    missingEveryOrg: { jinbe: ['org.audit:read', 'org.keys:read', 'org.members:read'] },
    grantedBy: ['staff-security', 'super_admins'],
  })),
}))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => null) } }))
vi.mock('../../../audit/deny.js', () => ({ denyAudit: vi.fn() }))
vi.mock('../../../services/redis-client.service.js', () => ({
  redisClientService: { isConnected: true },
  getRedisClient: () => ({ incr: async () => 1, expire: async () => 1, ttl: async () => 60 }),
}))
vi.mock('../../../services/redis-rbac.repository.js', async () => {
  const { roleDefinitions, everyOrgDefinitions, staffGroups } = await import('../../../policy/roles.js')
  const roles: Record<string, Record<string, string[]>> = { jinbe: { ...roleDefinitions(), member: ['users:read'] } }
  const groups = { ...staffGroups(), 'helpdesk-members': { jinbe: ['member'] } }
  return {
    redisRbacRepository: {
      getGroups: vi.fn(async () => groups),
      getRoles: vi.fn(async (s: string) => roles[s] ?? null),
      getEveryOrg: vi.fn(async (s: string) => (s === 'jinbe' ? everyOrgDefinitions() : null)),
    },
  }
})

import { requirePermission } from '../../../middleware/require-permission.js'
import { delegationGate } from '../../../middleware/delegation-gate.js'
import { forbiddenResponseSchema } from '../../../schemas/response-schemas.js'
import { recordRoute, resetDeclaredRoutes } from '../../../policy/declared-routes.js'
import { errorHandler } from '../../../middleware/error-handler.js'
import { assertNoSelfEscalation } from '../../../services/rbac-escalation-guard.js'

let app: FastifyInstance
beforeAll(async () => {
  resetDeclaredRoutes()
  app = Fastify()
  // The published route table the delegation gate reads each route's permission from.
  app.addHook('onRoute', (route) => recordRoute(route.method, route.url, [route.preHandler], () => false))
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const scopes = request.headers['x-scopes'] as string | undefined
    request.userContext = {
      id: 'u-1', email: 'ops@example.com', name: 'Ops',
      ...(scopes !== undefined
        ? { authVia: 'delegated' as const, delegation: { clientId: 'claude', scopes: scopes.split(' ').filter(Boolean), kind: 'personal' as const, via: 'auth-mcp' } }
        : { authVia: 'session' as const }),
    } as never
  })
  app.addHook('preHandler', delegationGate)
  // The response schema every guarded route declares for 403: the fields must survive it.
  const schema = { response: { 403: forbiddenResponseSchema } }
  app.post('/api/admin/users/:id/second-factor/reset', { schema, preHandler: requirePermission('users:reset_second_factor') }, async () => ({ ok: true }))
  app.delete('/api/admin/users/:id', { schema, preHandler: requirePermission('users:delete') }, async () => ({ ok: true }))
  app.setErrorHandler(errorHandler)
  // What POST /api/admin/rbac/groups does with the guard's refusal (rbac.service createGroup).
  app.post('/api/admin/rbac/groups', { schema }, async (request) => {
    await assertNoSelfEscalation({ kind: 'group', name: 'incident', after: { jinbe: ['security'] } }, { id: 'u-1', email: 'ops@example.com' })
    return { ok: true }
  })
  app.put('/api/admin/users/:id/state', { schema, preHandler: requirePermission('users:disable') }, async () => ({ ok: true }))
  await app.ready()
})
afterAll(() => app.close())

describe('a 403 for a missing permission', () => {
  it('names the permission, the groups granting it (the narrowest first), and who to ask', async () => {
    h.held = ['zones:write']
    const res = await app.inject({ method: 'POST', url: '/api/admin/users/u-2/second-factor/reset' })
    expect(res.statusCode).toBe(403)
    expect(res.json()).toEqual({
      error: 'Forbidden',
      code: 'permission_required',
      message: 'This needs users:reset_second_factor.',
      permission: 'users:reset_second_factor',
      grantedBy: ['staff-security', 'super_admins'],
      hint: 'Ask an administrator to add you to one of: staff-security, super_admins.',
    })
  })

  it('a permission only super_admin holds names super_admins — a permission like any other', async () => {
    const res = await app.inject({ method: 'DELETE', url: '/api/admin/users/u-2' })
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ error: 'Forbidden', code: 'permission_required', permission: 'users:delete', grantedBy: ['super_admins'] })
  })

  it('a key missing the scope keeps insufficient_scope and its reason, and says what grants the permission', async () => {
    h.held = ['users:disable']
    const res = await app.inject({ method: 'PUT', url: '/api/admin/users/u-2/state', headers: { 'x-scopes': 'users:read' } })
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({
      code: 'insufficient_scope',
      reason: 'scope_missing:users:disable',
      permission: 'users:disable',
      grantedBy: ['staff-security', 'super_admins'],
    })
  })

  it('a key refused outright (never delegable) carries no permission facts to act on', async () => {
    const res = await app.inject({ method: 'DELETE', url: '/api/admin/users/u-2', headers: { 'x-scopes': 'users:read' } })
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ code: 'delegation_refused' })
    expect(res.json().grantedBy).toBeUndefined()
  })
})

describe("the escalation guard's refusal, through the error handler", () => {
  it('keeps the message as `error` and adds code, what is missing, who grants it, the hint', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/admin/rbac/groups' })
    expect(res.statusCode).toBe(403)
    const body = res.json()
    expect(body.error).toMatch(/^Group 'incident' grants what you do not hold: /)
    expect(body).toMatchObject({
      code: 'grant_exceeds_own',
      missing: expect.arrayContaining(['users:reset_second_factor']),
      missingByScope: { jinbe: expect.arrayContaining(['users:reset_second_factor']), 'every_org:jinbe': ['org.audit:read', 'org.keys:read', 'org.members:read'] },
      grantedBy: ['staff-security', 'super_admins'],
      hint: 'Ask an administrator to add you to one of: staff-security, super_admins.',
    })
  })
})

describe('scopeRefusalFields', () => {
  it('names the permission and who grants it for scope_missing, nothing for another reason', async () => {
    const { scopeRefusalFields } = await import('../../../services/permission-refusal.js')
    expect(await scopeRefusalFields('scope_missing:users:disable')).toMatchObject({
      permission: 'users:disable',
      grantedBy: ['staff-security', 'super_admins'],
      hint: expect.stringContaining('use a key that carries it'),
    })
    expect(await scopeRefusalFields('delegation_ineligible:delete')).toEqual({})
  })
})
