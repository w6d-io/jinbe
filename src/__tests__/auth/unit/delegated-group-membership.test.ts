import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// Owner decision 2026-09-30: through a key, adding people to groups is normal work (with the key's
// step-up proof); removing them is a deletion and stays by hand. PUT /api/admin/users/:email/groups
// is decided per request by its guard: the global gate leaves it to the guard, except self-changes.

vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn().mockResolvedValue(undefined) } }))
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({ incr: async () => 1, expire: async () => 1, ttl: async () => 60 }),
}))
vi.mock('../../../middleware/require-permission.js', () => ({
  callerRights: async () => ({ permissions: ['groups.members:write', 'groups.members:revoke'], groups: ['super_admins'] }),
  demandPermissions: async () => true,
}))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: { findByEmail: async () => ({ id: 'bob-id' }) } }))
vi.mock('../../../services/organisation-store.js', () => ({ groupsForSubjects: async () => new Map([['bob-id', ['viewers']]]) }))

import { delegationGate } from '../../../middleware/delegation-gate.js'
import { requireMembershipChange } from '../../../middleware/require-membership-change.js'
import { recordRoute, resetDeclaredRoutes } from '../../../policy/declared-routes.js'

const DAY = 24 * 3600 * 1000
let app: FastifyInstance
beforeAll(async () => {
  resetDeclaredRoutes()
  app = Fastify()
  app.addHook('onRoute', (route) => recordRoute(route.method, route.url, [route.preHandler], () => false))
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const scopes = (request.headers['x-scopes'] as string | undefined) ?? ''
    request.userContext = {
      email: 'ann@acme.io', id: 'ann-id', name: 'Ann', authVia: 'delegated',
      delegation: { clientId: 'k1', scopes: scopes.split(' ').filter(Boolean), kind: 'personal', via: 'auth-mcp', keyStepUpAt: new Date(Date.now() - DAY).toISOString(), keyStepUpActions: request.headers['x-step-up-off'] !== '1' },
    } as never
  })
  app.addHook('preHandler', delegationGate)
  app.put('/api/admin/users/:email/groups', { preHandler: requireMembershipChange }, async () => ({ ok: true }))
  await app.ready()
})
afterAll(() => app.close())

const put = (email: string, groups: string[], scopes = 'groups.members:write groups.members:revoke', extra: Record<string, string> = {}) =>
  app.inject({ method: 'PUT', url: `/api/admin/users/${email}/groups`, headers: { 'x-scopes': scopes, ...extra }, payload: { groups } })

describe('group membership through a key', () => {
  it('adds someone to a group', async () => {
    const res = await put('bob@acme.io', ['viewers', 'staff-support'])
    expect(res.statusCode).toBe(200)
  })

  it('refuses a removal, and a change that both adds and removes', async () => {
    const removal = await put('bob@acme.io', [])
    expect(removal.statusCode).toBe(403)
    expect(removal.json().reason).toBe('delegation_ineligible:groups.members:revoke')
    const mixed = await put('bob@acme.io', ['staff-ops'])
    expect(mixed.statusCode).toBe(403)
  })

  it('refuses an addition the key has no scope for', async () => {
    const res = await put('bob@acme.io', ['viewers', 'staff-support'], 'users:read')
    expect(res.statusCode).toBe(403)
    expect(res.json().reason).toBe('scope_missing:groups.members:write')
  })

  // e2e A4 reported an add through a key without protected actions: auth-mcp found the user already in
  // the group and never called jinbe. Through jinbe, every addition needs the step-up.
  it('refuses an addition through a key created without protected actions', async () => {
    const res = await put('bob@acme.io', ['viewers', 'staff-support'], undefined, { 'x-step-up-off': '1' })
    expect(res.statusCode).toBe(422)
    expect(res.json().error).toBe('step_up_unavailable')
  })

  it('refuses a change to the caller themself', async () => {
    const res = await put('ann@acme.io', ['viewers', 'staff-support'])
    expect(res.statusCode).toBe(403)
    expect(res.json().reason).toBe('delegation_ineligible:self_change')
  })
})
