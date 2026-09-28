import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// /api/me/api-keys: 404 while delegated tokens are off, a person in a browser only; the per-org scope
// catalog of what the caller holds there; the list carries last use and the creator's address.

const ORG = '11111111-1111-1111-1111-111111111111'

const s = vi.hoisted(() => ({
  mcpConfig: {} as Record<string, string>,
  env: { DELEGATED_TOKENS_ENABLED: true },
  scopes: vi.fn(),
  list: vi.fn(async () => [] as unknown[]),
  decorate: vi.fn(async (_r: unknown, views: unknown[]) => views.map((v) => ({ ...(v as object), last_used_at: '2026-09-28T12:00:00.000Z' }))),
}))
vi.mock('../../../config/index.js', () => ({ env: s.env }))
// The MCP setting (mcp/settings.ts) read from rbac:config — unset is OFF, so each test saves it on (every org).
vi.mock('../../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: { getConfig: async () => s.mcpConfig, setConfig: vi.fn() } }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn().mockResolvedValue(undefined) } }))
vi.mock('../../../services/personal-key.service.js', () => ({ personalKeyService: { scopes: s.scopes, list: s.list } }))
vi.mock('../../../services/api-key-views.js', () => ({ decorateKeyViews: s.decorate }))

import { personalKeyRoutes } from '../../../routes/personal-key.routes.js'
import { ApiKeyError } from '../../../services/api-key.service.js'
import { AuthzUnavailableError } from '../../../authz/opa.js'
import { resetMcpSettingsCache } from '../../../mcp/settings.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const via = (request.headers['x-via'] as 'session' | 'machine' | 'delegated' | undefined) ?? 'session'
    request.userContext = { email: 'ann@acme.io', id: 'u1', name: 'Ann', authVia: via }
  })
  await app.register(personalKeyRoutes, { prefix: '/api/me/api-keys' })
  await app.ready()
})
afterAll(() => app.close())
beforeEach(() => {
  s.mcpConfig = { mcp: JSON.stringify({ enabled: true }) }
  resetMcpSettingsCache()
  s.env.DELEGATED_TOKENS_ENABLED = true
  s.scopes.mockReset().mockResolvedValue([{ scope: 'payroll:read', sites: ['payroll'] }])
})

const scopes = (query = `?organization_id=${ORG}`, headers: Record<string, string> = {}) =>
  app.inject({ url: `/api/me/api-keys/scopes${query}`, headers })

describe('GET /api/me/api-keys/scopes', () => {
  it("answers the org's catalog of what the caller holds there, in the org route's shape", async () => {
    const res = await scopes()
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ scopes: [{ scope: 'payroll:read', sites: ['payroll'] }] })
    expect(s.scopes).toHaveBeenCalledWith({ email: 'ann@acme.io' }, ORG)
  })

  it('is 404 while nothing is saved: MCP is off until an administrator opts in', async () => {
    s.mcpConfig = {}
    resetMcpSettingsCache()
    const res = await scopes()
    expect(res.statusCode).toBe(404)
    expect(res.json().message).toMatch(/turned off by an administrator/)
  })

  it('is 404, saying so, while an administrator turned MCP off', async () => {
    s.mcpConfig = { mcp: JSON.stringify({ enabled: false }) }
    resetMcpSettingsCache()
    const res = await scopes()
    expect(res.statusCode).toBe(404)
    expect(res.json().message).toMatch(/turned off by an administrator/)
    expect(s.scopes).not.toHaveBeenCalled()
  })

  it('is 404 while delegated tokens are off, 403 to a machine or delegated caller', async () => {
    s.env.DELEGATED_TOKENS_ENABLED = false
    expect((await scopes()).statusCode).toBe(404)
    s.env.DELEGATED_TOKENS_ENABLED = true
    expect((await scopes(undefined, { 'x-via': 'machine' })).statusCode).toBe(403)
    expect((await scopes(undefined, { 'x-via': 'delegated' })).statusCode).toBe(403)
    expect(s.scopes).not.toHaveBeenCalled()
  })

  it('needs an organization_id', async () => {
    expect((await scopes('')).statusCode).toBe(400)
    expect((await scopes('?organization_id=acme')).statusCode).toBe(400)
    expect(s.scopes).not.toHaveBeenCalled()
  })

  it('403 for a non-member, 503 (never an empty list) when OPA cannot be asked', async () => {
    s.scopes.mockRejectedValueOnce(new ApiKeyError(403, 'You are not a member of that organization'))
    const refused = await scopes()
    expect(refused.statusCode).toBe(403)
    expect(refused.json().message).toBe('You are not a member of that organization')
    s.scopes.mockRejectedValueOnce(new AuthzUnavailableError('opa down'))
    const down = await scopes()
    expect(down.statusCode).toBe(503)
    expect(down.json().error).toBe('policy_unavailable')
  })
})

describe('GET /api/me/api-keys', () => {
  it('returns the decorated views (last_used_at, created_by_email)', async () => {
    s.list.mockResolvedValueOnce([{ client_id: 'pk', created_by: 'u1', created_by_email: 'ann@acme.io', last_used_at: null }])
    const res = await app.inject({ url: '/api/me/api-keys' })
    expect(res.statusCode).toBe(200)
    expect(res.json().data[0]).toMatchObject({ client_id: 'pk', created_by_email: 'ann@acme.io', last_used_at: '2026-09-28T12:00:00.000Z' })
  })
})
