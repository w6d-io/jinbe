import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// Inviting a user through an MCP key (a delegated caller acting as its holder): POST /api/admin/users
// is declared users:create, and the gate lets a key whose scopes cover it through. What the guard asks
// ON TOP (groups.members:write for a group, users:recovery for the invite mail) must be covered by the
// token's scopes too, not only held by the user.

const h = vi.hoisted(() => ({
  held: ['users:create', 'users:recovery', 'groups.members:write'] as string[],
  created: [] as unknown[],
  invited: [] as string[],
  grants: [] as unknown[],
}))

vi.mock('../../../authz/opa.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../authz/opa.js')>()),
  rights: vi.fn(async () => ({ groups: [], roles: [], permissions: h.held })),
}))
vi.mock('../../../services/kratos.service.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../services/kratos.service.js')>()),
  kratosService: {
    createIdentity: vi.fn(async (body: { traits: Record<string, unknown> }) => {
      h.created.push(body)
      return { id: '55555555-5555-4555-8555-555555555555', schema_id: 'default', traits: body.traits, state: 'active' }
    }),
    sendRecoveryEmail: vi.fn(async (id: string) => { h.invited.push(id) }),
    deleteIdentity: vi.fn(),
  },
}))
vi.mock('../../../services/user-groups.service.js', () => ({
  userGroupsService: { applyGroupUpdate: vi.fn(async (input: unknown) => { h.grants.push(input); return { ok: true, response: {} } }) },
}))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { invalidateDirectoryStats: vi.fn(async () => {}), notifyBindingsChanged: vi.fn(async () => {}) } }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => null) } }))
vi.mock('../../../audit/deny.js', () => ({ denyAudit: vi.fn() }))
vi.mock('../../../services/redis-client.service.js', () => ({ getRedisClient: () => ({ incr: async () => 1, expire: async () => 1, ttl: async () => 60 }) }))
vi.mock('../../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { installRouteAccess } from '../../../policy/route-access.js'
import { delegationGate } from '../../../middleware/delegation-gate.js'
import { userManagementRoutes } from '../../../routes/user-management.routes.js'
import { declaredRoute } from '../../../policy/declared-routes.js'
import { denyAudit } from '../../../audit/deny.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const scopes = request.headers['x-scopes'] as string | undefined
    request.userContext = {
      id: 'holder-1', email: 'holder@x.test', name: 'Holder',
      ...(scopes !== undefined
        ? { authVia: 'delegated' as const, delegation: { clientId: 'claude', scopes: scopes.split(' ').filter(Boolean), kind: 'personal' as const, via: 'auth-mcp' } }
        : { authVia: 'session' as const }),
    } as never
  })
  app.addHook('preHandler', delegationGate)
  await app.register(userManagementRoutes, { prefix: '/api/admin' })
  await app.ready()
})
afterAll(() => app.close())
beforeEach(() => {
  h.held = ['users:create', 'users:recovery', 'groups.members:write']
  h.created = []
  h.invited = []
  h.grants = []
  vi.mocked(denyAudit).mockClear()
})
const refusedFor = () => vi.mocked(denyAudit).mock.calls.map((c) => c[1])

const invite = (payload: object, scopes?: string) =>
  app.inject({ method: 'POST', url: '/api/admin/users', payload, headers: scopes === undefined ? {} : { 'x-scopes': scopes } })

describe('POST /api/admin/users through a key', () => {
  it('is declared users:create', () => {
    expect(declaredRoute('POST', '/api/admin/users')).toMatchObject({ class: 'authorized', permission: 'users:create' })
  })

  it('creates the user for a key whose scopes cover users:create', async () => {
    const res = await invite({ email: 'new@x.test', name: 'New' }, 'users:create')
    expect(res.statusCode).toBe(201)
    expect(h.created).toHaveLength(1)
  })

  it('refuses a key without users:create: insufficient_scope, nothing created', async () => {
    const res = await invite({ email: 'new@x.test' }, 'users:read')
    expect(res.statusCode).toBe(403)
    expect(refusedFor()).toEqual(['scope_missing:users:create'])
    expect(h.created).toHaveLength(0)
  })

  it('sends the invite when the scopes also cover users:recovery', async () => {
    const res = await invite({ email: 'new@x.test', sendInvite: true }, 'users:create users:recovery')
    expect(res.statusCode).toBe(201)
    expect(h.invited).toHaveLength(1)
  })

  it('refuses the invite mail when the token lacks users:recovery, although the user holds it', async () => {
    const res = await invite({ email: 'new@x.test', sendInvite: true }, 'users:create')
    expect(res.statusCode).toBe(403)
    expect(refusedFor()).toEqual(['scope_missing:users:recovery'])
    expect(h.created).toHaveLength(0)
  })

  it('assigns groups through the grant gate only when the token covers groups.members:write', async () => {
    expect((await invite({ email: 'new@x.test', groups: ['billing'] }, 'users:create')).statusCode).toBe(403)
    expect(refusedFor()).toEqual(['scope_missing:groups.members:write'])
    expect(h.created).toHaveLength(0)
    const res = await invite({ email: 'new@x.test', groups: ['billing'] }, 'users:create groups.members:write')
    expect(res.statusCode).toBe(201)
    expect(h.grants).toHaveLength(1)
  })

  it('still refuses what the USER does not hold, whatever the token says', async () => {
    h.held = ['users:create']
    const res = await invite({ email: 'new@x.test', sendInvite: true }, 'users:create users:recovery')
    expect(res.statusCode).toBe(403)
    expect(h.created).toHaveLength(0)
  })

  it('keeps code and reason in the 403 body, so the client can say what is missing', async () => {
    const gate = await invite({ email: 'new@x.test' }, 'users:read')
    expect(gate.json()).toMatchObject({ error: 'Forbidden', code: 'insufficient_scope', reason: 'scope_missing:users:create' })
    const guard = await invite({ email: 'new@x.test', sendInvite: true }, 'users:create')
    expect(guard.json()).toMatchObject({ code: 'insufficient_scope', reason: 'scope_missing:users:recovery' })
  })

  it('a session refusal names the missing permission and who grants it, never a delegation reason', async () => {
    h.held = ['users:create']
    const res = await invite({ email: 'new@x.test', sendInvite: true })
    expect(res.statusCode).toBe(403)
    expect(Object.keys(res.json()).sort()).toEqual(['code', 'error', 'grantedBy', 'hint', 'message', 'permission'])
    expect(res.json()).toMatchObject({ error: 'Forbidden', code: 'permission_required', permission: 'users:recovery' })
  })

  it('leaves a session caller as it was', async () => {
    expect((await invite({ email: 'new@x.test', sendInvite: true })).statusCode).toBe(201)
  })
})
