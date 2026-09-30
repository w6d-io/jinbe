import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// "Signed-in apps" (kuma Connections): a person's MCP browser sign-ins, disconnecting one or all of
// them, sign out everywhere taking them too, and the sweep of unconsented / orphaned / expired
// registrations.

const NOW = Date.now()
const iso = (ms: number) => new Date(ms).toISOString()

const h = vi.hoisted(() => ({
  env: { DELEGATED_TOKENS_ENABLED: true, MCP_OAUTH_ISSUER: 'https://hydra.example.com/' } as Record<string, unknown>,
  config: {} as Record<string, string>,
  sessions: [] as unknown[],
  clients: new Map<string, Record<string, unknown>>(),
  listConsentSessions: vi.fn(),
  revokeConsentSessions: vi.fn(async () => undefined),
  deleteClient: vi.fn(async () => undefined),
  listAllClients: vi.fn(),
  forgetClient: vi.fn(),
  lastUsed: new Map<string, string>(),
  emit: vi.fn(async () => 'id'),
}))

vi.mock('../../config/index.js', async (orig) => {
  const real = (await orig()) as { env: object }
  Object.setPrototypeOf(h.env, real.env)
  return { ...real, env: h.env }
})
vi.mock('../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: { getConfig: async () => h.config, setConfig: vi.fn() } }))
vi.mock('../../services/hydra-flows.service.js', () => ({ hydraFlows: { listConsentSessions: h.listConsentSessions, revokeConsentSessions: h.revokeConsentSessions } }))
vi.mock('../../services/hydra.service.js', async (orig) => {
  const real = (await orig()) as { HydraApiError: new (s: number, m: string) => Error }
  return {
    ...real,
    hydraService: {
      getClient: vi.fn(async (id: string) => {
        const c = h.clients.get(id)
        if (!c) throw new real.HydraApiError(404, 'Not Found')
        return c
      }),
      deleteClient: h.deleteClient,
      listAllClients: h.listAllClients,
    },
  }
})
vi.mock('../../services/delegated-token.service.js', () => ({ delegatedTokenService: { forgetClient: h.forgetClient } }))
vi.mock('../../services/api-key-last-used.js', () => ({ lastUsedOf: vi.fn(async () => h.lastUsed), forgetApiKeyUse: vi.fn() }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../middleware/require-permission.js', async () => (await import('../helpers/permission-stand-ins.js')).permissionStandIn({ readHeader: 'x-test-admin' }))
vi.mock('../../middleware/require-admin.js', async () => (await import('../helpers/permission-stand-ins.js')).adminStandIn())

import { installRouteAccess } from '../../policy/route-access.js'
import { mcpConnectionsAdminRoutes, mcpConnectionsRoutes } from '../../oauth/routes.js'
import { resetMcpSettingsCache } from '../../mcp/settings.js'
import { sweepMcpClients } from '../../oauth/gc.js'
import { revokeAllConnectionsQuietly } from '../../oauth/connections.js'

const mcp = (id: string, bound: string | null, registeredAgoMs = 2 * 3600_000) => ({
  client_id: id, client_name: `App ${id}`, redirect_uris: ['http://localhost:53682/callback'],
  metadata: { kind: 'mcp_oauth', bound_subject: bound, registered_at: iso(NOW - registeredAgoMs) },
})
const consent = (client: Record<string, unknown>, ext: Record<string, unknown> = {}, grant = ['mcp', 'offline_access', 'sites:read']) => ({
  consent_request: { challenge: 'x', client },
  grant_scope: grant,
  handled_at: iso(NOW - 3600_000),
  session: { access_token: { kind: 'oauth', scope_mode: 'chosen', step_up_actions: false, granted_at: iso(NOW - 3600_000), grant_expires_at: iso(NOW + 29 * 86_400_000), ...ext } },
})

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const via = (request.headers['x-via'] as string | undefined) ?? 'session'
    request.userContext = { email: 'ann@acme.io', id: 'user-1', name: 'Ann', authVia: via } as never
  })
  await app.register(mcpConnectionsRoutes, { prefix: '/api/me/mcp/connections' })
  await app.register(mcpConnectionsAdminRoutes, { prefix: '/api/admin' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  h.config = { mcp: JSON.stringify({ enabled: true }) }
  h.clients = new Map([['c-1', mcp('c-1', 'user-1')], ['c-2', mcp('c-2', 'user-1')], ['org-key', { client_id: 'org-key', metadata: { organization_id: 'acme' } }]])
  h.sessions = [
    consent(h.clients.get('c-1')!, { scope_mode: 'all', step_up_actions: true, second_factor_at: iso(NOW - 3600_000) }, ['mcp', 'offline_access', 'sites:read', 'sites:apply']),
    consent(h.clients.get('c-2')!),
    // A machine client's consent (not an MCP registration) is never listed nor touched.
    consent(h.clients.get('org-key')!),
  ]
  h.listConsentSessions.mockReset().mockImplementation(async () => h.sessions)
  h.revokeConsentSessions.mockClear()
  h.deleteClient.mockClear()
  h.forgetClient.mockClear()
  h.listAllClients.mockReset().mockResolvedValue([])
  h.lastUsed = new Map([['c-2', iso(NOW - 60_000)]])
  h.emit.mockClear()
  resetMcpSettingsCache()
})

describe('GET /api/me/mcp/connections', () => {
  it('lists MCP sign-ins only, with mode, scopes, the protected-actions window and last use', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/me/mcp/connections' })
    expect(res.statusCode).toBe(200)
    const { data, total } = res.json()
    expect(total).toBe(2)
    const c1 = data.find((c: { client_id: string }) => c.client_id === 'c-1')
    expect(c1).toEqual({
      client_id: 'c-1', client_name: 'App c-1', redirect_host: 'localhost:53682', granted_at: iso(NOW - 3600_000),
      grant_expires_at: iso(NOW + 29 * 86_400_000), scope_mode: 'all', scopes: [], step_up_actions: true,
      step_up_until: iso(NOW - 3600_000 + 12 * 3600_000), last_used_at: null,
    })
    const c2 = data.find((c: { client_id: string }) => c.client_id === 'c-2')
    expect(c2).toMatchObject({ scope_mode: 'chosen', scopes: ['sites:read'], step_up_actions: false, step_up_until: null, last_used_at: iso(NOW - 60_000) })
    expect(h.listConsentSessions).toHaveBeenCalledWith('user-1')
  })

  it('is 404 while MCP is off, and refused to a delegated or machine caller', async () => {
    expect((await app.inject({ method: 'GET', url: '/api/me/mcp/connections', headers: { 'x-via': 'delegated' } })).statusCode).toBe(403)
    expect((await app.inject({ method: 'GET', url: '/api/me/mcp/connections', headers: { 'x-via': 'machine' } })).statusCode).toBe(403)
    h.config = { mcp: JSON.stringify({ enabled: false }) }
    resetMcpSettingsCache()
    expect((await app.inject({ method: 'GET', url: '/api/me/mcp/connections' })).statusCode).toBe(404)
  })

  it('answers 503 when Hydra cannot be read', async () => {
    h.listConsentSessions.mockRejectedValue(new Error('ECONNREFUSED'))
    expect((await app.inject({ method: 'GET', url: '/api/me/mcp/connections' })).statusCode).toBe(503)
  })
})

describe('DELETE /api/me/mcp/connections/:clientId', () => {
  it('revokes the consent (and its tokens), drops jinbe caches, deletes the bound registration, audits', async () => {
    const res = await app.inject({ method: 'DELETE', url: '/api/me/mcp/connections/c-1' })
    expect(res.statusCode).toBe(204)
    expect(h.revokeConsentSessions).toHaveBeenCalledWith('user-1', 'c-1')
    expect(h.forgetClient).toHaveBeenCalledWith('c-1')
    expect(h.deleteClient).toHaveBeenCalledWith('c-1')
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ v1Event: 'mcp.oauth.revoked', targetId: 'c-1' }))
  })

  it("keeps a registration bound to somebody else (revokes only this person's consent)", async () => {
    h.clients.set('c-1', mcp('c-1', 'user-9'))
    expect((await app.inject({ method: 'DELETE', url: '/api/me/mcp/connections/c-1' })).statusCode).toBe(204)
    expect(h.revokeConsentSessions).toHaveBeenCalledWith('user-1', 'c-1')
    expect(h.deleteClient).not.toHaveBeenCalled()
  })

  it('404 for an unknown client, a machine client, or one the person never signed in with', async () => {
    expect((await app.inject({ method: 'DELETE', url: '/api/me/mcp/connections/nope' })).statusCode).toBe(404)
    expect((await app.inject({ method: 'DELETE', url: '/api/me/mcp/connections/org-key' })).statusCode).toBe(404)
    h.clients.set('c-3', mcp('c-3', 'user-9'))
    expect((await app.inject({ method: 'DELETE', url: '/api/me/mcp/connections/c-3' })).statusCode).toBe(404)
    expect(h.revokeConsentSessions).not.toHaveBeenCalled()
  })

  it('a delegated caller may disconnect (protective)', async () => {
    expect((await app.inject({ method: 'DELETE', url: '/api/me/mcp/connections/c-2', headers: { 'x-via': 'delegated' } })).statusCode).toBe(204)
  })
})

describe('disconnecting all of a person\'s sign-ins', () => {
  it('DELETE /api/admin/users/:id/mcp-connections needs sessions:revoke and revokes every MCP consent', async () => {
    expect((await app.inject({ method: 'DELETE', url: '/api/admin/users/user-1/mcp-connections' })).statusCode).toBe(403)
    const res = await app.inject({ method: 'DELETE', url: '/api/admin/users/user-1/mcp-connections', headers: { 'x-test-perms': 'sessions:revoke', 'x-test-mfa': '1' } })
    expect(res.statusCode).toBe(204)
    expect(h.revokeConsentSessions.mock.calls.map((c) => (c as unknown[])[1]).sort()).toEqual(['c-1', 'c-2'])
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ v1Event: 'mcp.oauth.revoked_all', targetId: 'user-1', targetType: 'user' }))
  })

  it('sign out everywhere / a second-factor reset never fails on Hydra being down', async () => {
    h.listConsentSessions.mockRejectedValue(new Error('ECONNREFUSED'))
    expect(await revokeAllConnectionsQuietly('user-1')).toEqual([])
  })
})

describe('sweepMcpClients', () => {
  it('deletes unconsented registrations older than 1 h and orphans; revokes sign-ins past their end', async () => {
    const fresh = mcp('fresh', null, 10 * 60_000)
    const stale = mcp('stale', null)
    const orphan = mcp('orphan', 'user-1')
    const live = mcp('c-2', 'user-1')
    const expired = mcp('c-1', 'user-1')
    h.sessions = [consent(expired, { grant_expires_at: iso(NOW - 1000) }), consent(live)]
    h.listAllClients.mockResolvedValue([fresh, stale, orphan, live, expired, { client_id: 'other', metadata: { kind: 'personal' } }])
    const r = await sweepMcpClients(NOW)
    expect(r).toEqual({ unconsented: 1, bound: 1, deleted: 3, expired: 1 })
    expect(h.deleteClient.mock.calls.map((c) => (c as unknown[])[0]).sort()).toEqual(['c-1', 'orphan', 'stale'])
    expect(h.revokeConsentSessions).toHaveBeenCalledWith('user-1', 'c-1')
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ v1Event: 'mcp.oauth.grant_expired', targetId: 'c-1' }))
    // One consent listing per person, however many of their registrations are swept.
    expect(h.listConsentSessions).toHaveBeenCalledTimes(1)
    expect(h.listAllClients).toHaveBeenCalledWith(500, 10, 'mcp-dcr')
  })
})
