import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// A delegated caller (user through a client): scope must cover the route permission, the token is
// bound to no org, ineligible routes are refused even
// for a super admin, no self-change, and a permission-less route is read-only. A session caller is
// untouched.

vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn().mockResolvedValue(undefined) } }))

import { delegationGate } from '../../../middleware/delegation-gate.js'
import { enforcing, recordRoute, resetDeclaredRoutes } from '../../../policy/declared-routes.js'
import { auditEventService } from '../../../services/audit-event.service.js'

const ACME = '11111111-1111-1111-1111-111111111111'
const GLOBEX = '22222222-2222-2222-2222-222222222222'
const guard = (permission: string) => enforcing(async () => {}, permission)
const ok = async () => ({ ok: true })

let app: FastifyInstance
beforeAll(async () => {
  resetDeclaredRoutes()
  app = Fastify()
  app.addHook('onRoute', (route) => recordRoute(route.method, route.url, [route.preHandler], (p) => p === '/api/health'))
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const scopes = request.headers['x-scopes'] as string | undefined
    request.userContext = {
      email: 'ann@acme.io', id: 'user-1', name: 'Ann',
      ...(scopes !== undefined
        ? { authVia: 'delegated' as const, delegation: { clientId: 'claude', scopes: scopes.split(' ').filter(Boolean), kind: 'oauth' as const, via: 'auth-mcp' } }
        : { authVia: 'session' as const }),
    }
  })
  app.addHook('preHandler', delegationGate)

  app.get('/api/health', ok)
  app.get('/api/me/permissions', ok)
  app.put('/api/me/preferences', ok)
  app.get('/api/admin/sites', { preHandler: guard('sites:read') }, ok)
  app.put('/api/admin/sites/:name', { preHandler: guard('sites:write') }, ok)
  app.post('/api/admin/sites/:name/apply', { preHandler: guard('sites:apply') }, ok)
  app.post('/api/admin/sites/requests/:id/approve', { preHandler: guard('sites.requests:approve') }, ok)
  app.get('/api/organizations/:organizationId/users', { preHandler: guard('org:manage_users') }, ok)
  app.put('/api/organizations/:organizationId/users/:id/groups', { preHandler: guard('org:manage_users') }, ok)
  app.post('/api/organizations/:organizationId/api-keys', { preHandler: guard('org.keys:write') }, ok)
  app.get('/api/organizations/:organizationId/api-keys', { preHandler: guard('org.keys:read') }, ok)
  app.post('/api/me/api-keys', ok)
  app.put('/api/admin/settings/second-factor', { preHandler: guard('settings.signin:write') }, ok)
  app.get('/scim/v2/Users', ok)
  app.put('/api/admin/rbac/org-admin-map', { preHandler: guard('org.admins:write') }, ok)
  app.delete('/api/admin/users/:id', { preHandler: guard('users:delete') }, ok)
  app.get('/api/admin/legacy', { preHandler: guard('*') }, ok)
  await app.ready()
})
afterAll(() => app.close())

const call = (method: 'GET' | 'PUT' | 'POST' | 'DELETE', url: string, scopes?: string) =>
  app.inject({ method, url, headers: scopes === undefined ? {} : { 'x-scopes': scopes } })

describe('delegation gate', () => {
  it('leaves a session caller alone, everywhere', async () => {
    expect((await call('POST', '/api/organizations/' + ACME + '/api-keys')).statusCode).toBe(200)
    expect((await call('POST', '/api/admin/sites/x/apply')).statusCode).toBe(200)
  })

  it('needs a scope covering the route permission (dotted ancestors count, wildcards never)', async () => {
    expect((await call('GET', '/api/admin/sites', 'sites:read')).statusCode).toBe(200)
    expect((await call('GET', '/api/admin/sites', 'sites.x:read')).statusCode).toBe(403)
    const denied = await call('PUT', '/api/admin/sites/x', 'sites:read')
    expect(denied.statusCode).toBe(403)
    expect(denied.json()).toMatchObject({ code: 'insufficient_scope', reason: 'scope_missing:sites:write' })
    expect((await call('PUT', '/api/admin/sites/x', '* sites:*')).statusCode).toBe(403)
    expect(auditEventService.emit).toHaveBeenCalledWith(expect.objectContaining({ verb: 'deny', reason: 'scope_missing:sites:write' }))
  })

  it('binds to no organization: any org\'s route is the user\'s to be authorized for, by its own guard', async () => {
    expect((await call('GET', `/api/organizations/${ACME}/users`, 'org:manage_users')).statusCode).toBe(200)
    expect((await call('GET', `/api/organizations/${GLOBEX}/users`, 'org:manage_users')).statusCode).toBe(200)
  })

  it.each([
    // The catalogue's `never`: key creation, the org-admin roster, approvals, deletions — whatever the scope.
    ['POST', `/api/organizations/${ACME}/api-keys`, 'org.keys:write', 'delegation_ineligible:org.keys:write'],
    ['PUT', '/api/admin/rbac/org-admin-map', 'org.admins:write', 'delegation_ineligible:org.admins:write'],
    ['POST', '/api/admin/sites/requests/r1/approve', 'sites.requests:approve', 'delegation_ineligible:sites.requests:approve'],
    ['DELETE', '/api/admin/users/u-2', 'users:delete admin:write', 'delegation_ineligible:users:delete'],
    ['PUT', '/api/admin/settings/second-factor', 'settings.signin:write', 'delegation_ineligible:settings.signin:write'],
    ['GET', '/api/admin/legacy', 'admin:read', 'delegation_ineligible:*'],
    // The backstop list: routes with no catalogue permission to decide on.
    ['POST', '/api/me/api-keys', '', 'delegation_ineligible:api_keys'],
    ['GET', '/scim/v2/Users', 'users:read', 'delegation_ineligible:scim'],
  ] as const)('refuses ineligible %s %s even with a matching scope', async (method, url, scopes, reason) => {
    const res = await call(method, url, scopes)
    expect(res.statusCode).toBe(403)
    expect(res.json().reason).toBe(reason)
  })

  it.each([
    // Owner decision: anything the user can do except the catalogue's `never`. A step-up permission
    // passes this gate and is left to requireRecentMfa.
    ['POST', '/api/admin/sites/x/apply', 'sites:apply'],
    ['GET', `/api/organizations/${ACME}/api-keys`, 'org.keys:read'],
  ] as const)('lets %s %s through with a scope granting it (delegable: direct)', async (method, url, scopes) => {
    expect((await call(method, url, scopes)).statusCode).toBe(200)
  })

  it('a legacy name still grants its catalogue permissions as a scope, for one release', async () => {
    expect((await call('PUT', '/api/admin/sites/x', 'admin:write')).statusCode).toBe(200)
    expect((await call('POST', '/api/admin/sites/x/apply', 'admin:write')).statusCode).toBe(403)
  })

  it("refuses a change to the caller's own groups (no self-grant), not to somebody else's", async () => {
    const self = await call('PUT', `/api/organizations/${ACME}/users/user-1/groups`, 'org:manage_users')
    expect(self.statusCode).toBe(403)
    expect(self.json().reason).toBe('delegation_ineligible:self_change')
    expect((await call('PUT', `/api/organizations/${ACME}/users/user-2/groups`, 'org:manage_users')).statusCode).toBe(200)
  })

  it('a permission-less route is read-only; a public one is open', async () => {
    expect((await call('GET', '/api/me/permissions', '')).statusCode).toBe(200)
    expect((await call('PUT', '/api/me/preferences', 'sites:write')).json().reason).toBe('delegation_no_scope_for_write')
    expect((await call('GET', '/api/health', '')).statusCode).toBe(200)
  })
})
