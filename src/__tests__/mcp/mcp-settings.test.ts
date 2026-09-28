import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// AI assistants (MCP): the administrator's switch (rbac:config mcp) under the deployment's ceiling
// (DELEGATED_TOKENS_ENABLED), its settings routes and the signed-in status kuma reads.

const h = vi.hoisted(() => ({
  config: {} as Record<string, string>,
  redisDown: false,
  emit: vi.fn(async () => 'id'),
  clearCache: vi.fn(),
  env: { DELEGATED_TOKENS_ENABLED: true } as Record<string, unknown>,
}))

vi.mock('../../config/index.js', () => ({ env: h.env }))
vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getConfig: vi.fn(async () => {
      if (h.redisDown) throw new Error('ECONNREFUSED')
      return { ...h.config }
    }),
    setConfig: vi.fn(async (k: string, v: string) => { h.config[k] = v }),
  },
}))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../services/delegated-token.service.js', () => ({ delegatedTokenService: { clearCache: h.clearCache } }))
vi.mock('../../middleware/require-admin.js', () => ({
  requireAdmin: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-admin']) return reply.status(403).send({ error: 'Forbidden' })
  },
  requireSuperAdmin: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden' })
  },
  requireRecentMfa: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-mfa']) return reply.status(422).send({ error: 'reauth_required' })
  },
}))

import { mcpSettingsRoutes, mcpStatusRoutes } from '../../mcp/routes.js'
import { MCP_SETTINGS_KEY, defaultMcpSettings, mcpGate, parseMcpSettings, resetMcpSettingsCache, validateMcpSettings } from '../../mcp/settings.js'
import { isPublicRoute } from '../../middleware/require-auth.js'

const ORG_A = '11111111-1111-1111-1111-111111111111'
const ORG_B = '22222222-2222-2222-2222-222222222222'
const store = (v: unknown) => { h.config[MCP_SETTINGS_KEY] = JSON.stringify(v); resetMcpSettingsCache() }

beforeEach(() => {
  h.config = {}
  h.redisDown = false
  h.env.DELEGATED_TOKENS_ENABLED = true
  delete h.env.MCP_PUBLIC_URL
  h.emit.mockClear()
  h.clearCache.mockClear()
  resetMcpSettingsCache()
})

describe('settings', () => {
  it('unset is OFF until an administrator opts in; no URL, 30 days, every org', () => {
    expect(parseMcpSettings(undefined)).toEqual({ enabled: false, serverUrl: null, personalKeys: { maxDays: 30 }, allowedOrgs: 'all' })
    expect(parseMcpSettings('not json')).toEqual(defaultMcpSettings())
  })

  it('accepts a clean document and canonicalises the org list', () => {
    const r = validateMcpSettings({ enabled: false, serverUrl: 'https://mcp.example.com/mcp', personalKeys: { maxDays: 7 }, allowedOrgs: [ORG_B, ORG_A.toUpperCase(), ORG_B] })
    expect(r).toEqual({ ok: true, value: { enabled: false, serverUrl: 'https://mcp.example.com/mcp', personalKeys: { maxDays: 7 }, allowedOrgs: [ORG_A, ORG_B] } })
    expect(validateMcpSettings({ enabled: true, serverUrl: '' })).toMatchObject({ ok: true, value: { serverUrl: null } })
  })

  it.each([
    ['a non-https URL', { serverUrl: 'http://mcp.example.com' }, 'serverUrl'],
    ['a URL with credentials', { serverUrl: 'https://u:p@mcp.example.com' }, 'serverUrl'],
    ['more than 30 days', { personalKeys: { maxDays: 31 } }, 'personalKeys.maxDays'],
    ['zero days', { personalKeys: { maxDays: 0 } }, 'personalKeys.maxDays'],
    ['an org that is not an id', { allowedOrgs: ['acme'] }, 'allowedOrgs'],
    ['an empty org list', { allowedOrgs: [] }, 'allowedOrgs'],
    ['a non-boolean switch', { enabled: 'yes' }, 'enabled'],
  ])('refuses %s', (_l, input, field) => {
    const r = validateMcpSettings({ enabled: true, ...input })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.problems.map((p) => p.field)).toContain(field)
  })

  it('gate: the env ceiling wins, then the switch; an unreadable setting refuses', async () => {
    expect(await mcpGate()).toMatchObject({ on: false, off: 'administrator' }) // nothing saved: off
    store({ enabled: true })
    expect(await mcpGate()).toMatchObject({ on: true })
    store({ enabled: false })
    expect(await mcpGate()).toMatchObject({ on: false, off: 'administrator' })
    store({ enabled: true })
    h.env.DELEGATED_TOKENS_ENABLED = false
    expect(await mcpGate()).toEqual({ on: false, off: 'deployment' })
    h.env.DELEGATED_TOKENS_ENABLED = true
    resetMcpSettingsCache()
    h.redisDown = true
    expect(await mcpGate()).toEqual({ on: false, off: 'unavailable' })
  })

  it('keeps answering the last known document through a Redis outage', async () => {
    store({ enabled: false })
    expect(await mcpGate()).toMatchObject({ off: 'administrator' })
    h.redisDown = true
    vi.useFakeTimers()
    vi.setSystemTime(Date.now() + 10_000)
    expect(await mcpGate()).toMatchObject({ off: 'administrator' })
    vi.useRealTimers()
  })
})

describe('routes', () => {
  let app: FastifyInstance
  beforeAll(async () => {
    app = Fastify()
    app.addHook('onRequest', async (request: FastifyRequest) => {
      if (request.headers['x-anon']) return
      request.userContext = { email: 'ann@acme.io', id: 'u1', name: 'Ann', authVia: 'session' }
    })
    await app.register(async (api) => {
      await api.register(mcpSettingsRoutes, { prefix: '/admin/settings' })
      await api.register(mcpStatusRoutes, { prefix: '/mcp' })
    }, { prefix: '/api' })
    await app.ready()
  })
  afterAll(() => app.close())

  const put = (body: unknown, headers: Record<string, string> = { 'x-test-write': '1', 'x-test-mfa': '1' }) =>
    app.inject({ method: 'PUT', url: '/api/admin/settings/mcp', headers, payload: body as Record<string, unknown> })
  const status = (headers: Record<string, string> = {}) => app.inject({ url: '/api/mcp/status', headers })

  it('GET is for admins and shows the ceiling and the effective state', async () => {
    expect((await app.inject({ url: '/api/admin/settings/mcp' })).statusCode).toBe(403)
    const unset = (await app.inject({ url: '/api/admin/settings/mcp', headers: { 'x-test-admin': '1' } })).json()
    expect(unset).toMatchObject({ settings: { enabled: false }, ceiling: { enabled: true }, effective: false })
    store({ enabled: true })
    const res = await app.inject({ url: '/api/admin/settings/mcp', headers: { 'x-test-admin': '1' } })
    expect(res.json()).toMatchObject({ settings: { enabled: true }, ceiling: { enabled: true, note: null }, effective: true })
    h.env.DELEGATED_TOKENS_ENABLED = false
    const off = (await app.inject({ url: '/api/admin/settings/mcp', headers: { 'x-test-admin': '1' } })).json()
    expect(off).toMatchObject({ settings: { enabled: true }, ceiling: { enabled: false }, effective: false })
    expect(off.ceiling.note).toMatch(/DELEGATED_TOKENS_ENABLED is false/)
  })

  it('PUT needs super_admin and a fresh second factor', async () => {
    expect((await put({ enabled: false }, {})).statusCode).toBe(403)
    expect((await put({ enabled: false }, { 'x-test-write': '1' })).statusCode).toBe(422)
    expect(h.config[MCP_SETTINGS_KEY]).toBeUndefined()
  })

  it('PUT saves, audits config.mcp.changed, drops cached tokens when the switch flips, and takes effect at once', async () => {
    store({ enabled: true })
    const res = await put({ enabled: false, serverUrl: 'https://mcp.example.com/mcp', personalKeys: { maxDays: 7 }, allowedOrgs: 'all' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ settings: { enabled: false, serverUrl: 'https://mcp.example.com/mcp', personalKeys: { maxDays: 7 } }, effective: false })
    expect(await mcpGate()).toMatchObject({ on: false, off: 'administrator' })
    expect(h.clearCache).toHaveBeenCalledTimes(1)
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ target: 'mcp', v1Event: 'config.mcp.changed', details: expect.objectContaining({ before: expect.objectContaining({ enabled: true }), after: expect.objectContaining({ enabled: false }) }) }))
    await put({ enabled: false, serverUrl: 'https://mcp.example.com/other' })
    expect(h.clearCache).toHaveBeenCalledTimes(1)
  })

  it('PUT refuses an invalid document with field problems', async () => {
    const res = await put({ enabled: true, serverUrl: 'ftp://x', personalKeys: { maxDays: 90 } })
    expect(res.statusCode).toBe(400)
    expect(res.json().problems.map((p: { field: string }) => p.field)).toEqual(['serverUrl', 'personalKeys.maxDays'])
  })

  it('PUT under a closed ceiling saves but says MCP stays off', async () => {
    h.env.DELEGATED_TOKENS_ENABLED = false
    const res = await put({ enabled: true })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ settings: { enabled: true }, ceiling: { enabled: false }, effective: false })
  })

  it('status: signed-in only; on, off by an administrator, off by the deployment', async () => {
    expect(isPublicRoute('/api/mcp/status')).toBe(true) // bypasses the session gate, so it checks the session itself
    expect((await status({ 'x-anon': '1' })).statusCode).toBe(401)
    expect((await status()).json()).toMatchObject({ enabled: false, off: 'administrator' }) // nothing saved yet
    store({ enabled: true, serverUrl: 'https://mcp.example.com/mcp', personalKeys: { maxDays: 7 } })
    expect((await status()).json()).toEqual({ enabled: true, serverUrl: 'https://mcp.example.com/mcp', off: null, personalKeys: { maxDays: 7 } })
    store({ enabled: false, serverUrl: 'https://mcp.example.com/mcp' })
    expect((await status()).json()).toMatchObject({ enabled: false, off: 'administrator' })
    h.env.DELEGATED_TOKENS_ENABLED = false
    expect((await status()).json()).toEqual({ enabled: false, serverUrl: null, off: 'deployment', personalKeys: null })
  })

  it('the deployment address (MCP_PUBLIC_URL) is shown until an administrator saves another; saving it unchanged stores none', async () => {
    h.env.MCP_PUBLIC_URL = 'https://mcp.authdev.example.com/mcp'
    store({ enabled: true })
    expect((await status()).json()).toMatchObject({ enabled: true, serverUrl: 'https://mcp.authdev.example.com/mcp' })
    const view = (await app.inject({ url: '/api/admin/settings/mcp', headers: { 'x-test-admin': '1' } })).json()
    expect(view).toMatchObject({ settings: { serverUrl: 'https://mcp.authdev.example.com/mcp' }, defaults: { serverUrl: 'https://mcp.authdev.example.com/mcp' } })

    await put({ enabled: true, serverUrl: 'https://mcp.authdev.example.com/mcp' })
    expect(JSON.parse(h.config[MCP_SETTINGS_KEY]).serverUrl).toBeNull() // keeps following the deployment
    h.env.MCP_PUBLIC_URL = 'https://mcp.moved.example.com/mcp'
    expect((await status()).json()).toMatchObject({ serverUrl: 'https://mcp.moved.example.com/mcp' })

    await put({ enabled: true, serverUrl: 'https://mcp.custom.example.com/mcp' })
    expect((await status()).json()).toMatchObject({ serverUrl: 'https://mcp.custom.example.com/mcp' })

    h.env.MCP_PUBLIC_URL = 'http://auth-mcp:3100/mcp' // not https: no address rather than a bad one
    store({ enabled: true })
    expect((await status()).json()).toMatchObject({ serverUrl: null })
    h.env.DELEGATED_TOKENS_ENABLED = false
    expect((await status()).json()).toMatchObject({ serverUrl: null, off: 'deployment' })
  })
})
