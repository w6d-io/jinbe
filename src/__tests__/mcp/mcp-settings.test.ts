import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { installRouteAccess } from '../../policy/route-access.js'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// AI assistants (MCP): the administrator's switch (rbac:config mcp) under the deployment's ceiling
// (DELEGATED_TOKENS_ENABLED), its settings routes and the signed-in status kuma reads.

const h = vi.hoisted(() => ({
  config: {} as Record<string, string>,
  redisDown: false,
  emit: vi.fn(async () => 'id'),
  clearCache: vi.fn(),
  env: { DELEGATED_TOKENS_ENABLED: true } as Record<string, unknown>,
  groups: ['staff'] as string[],
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
vi.mock('../../authz/opa.js', () => ({ rights: vi.fn(async () => ({ groups: h.groups, roles: [], permissions: [] })) }))
vi.mock('../../services/delegated-token.service.js', () => ({ delegatedTokenService: { clearCache: h.clearCache } }))
vi.mock('../../middleware/require-permission.js', async () => (await import('../helpers/permission-stand-ins.js')).permissionStandIn({ readHeader: 'x-test-admin' }))
vi.mock('../../middleware/require-admin.js', async () => (await import('../helpers/permission-stand-ins.js')).adminStandIn())

import { mcpSettingsRoutes, mcpStatusRoutes } from '../../mcp/routes.js'
import { MCP_SETTINGS_KEY, defaultMcpSettings, getMcpSettings, groupAllowed, mcpGate, parseMcpSettings, resetMcpSettingsCache, validateMcpSettings } from '../../mcp/settings.js'
import { isPublicRoute } from '../../middleware/require-auth.js'

const store = (v: unknown) => { h.config[MCP_SETTINGS_KEY] = JSON.stringify(v); resetMcpSettingsCache() }

beforeEach(() => {
  h.config = {}
  h.redisDown = false
  h.groups = ['staff']
  h.env.DELEGATED_TOKENS_ENABLED = true
  delete h.env.MCP_PUBLIC_URL
  h.emit.mockClear()
  h.clearCache.mockClear()
  resetMcpSettingsCache()
})

describe('settings', () => {
  it('unset is OFF until an administrator opts in; no URL, 30 days, every group', () => {
    expect(parseMcpSettings(undefined)).toEqual({ enabled: false, serverUrl: null, personalKeys: { maxDays: 30 }, allowedGroups: 'all', oauth: { enabled: true, maxDays: 30, protectedActions: 'window', protectedActionsHours: 12 } })
    expect(parseMcpSettings('not json')).toEqual(defaultMcpSettings())
  })

  it('accepts a clean document and canonicalises the group list', () => {
    const r = validateMcpSettings({ enabled: false, serverUrl: 'https://mcp.example.com/mcp', personalKeys: { maxDays: 7 }, allowedGroups: ['support', ' ops ', 'support'] })
    expect(r).toEqual({ ok: true, value: { enabled: false, serverUrl: 'https://mcp.example.com/mcp', personalKeys: { maxDays: 7 }, allowedGroups: ['ops', 'support'], oauth: { enabled: true, maxDays: 30, protectedActions: 'window', protectedActionsHours: 12 } } })
    expect(validateMcpSettings({ enabled: true, serverUrl: '' })).toMatchObject({ ok: true, value: { serverUrl: null } })
  })

  it.each([
    ['a non-https URL', { serverUrl: 'http://mcp.example.com' }, 'serverUrl'],
    ['a URL with credentials', { serverUrl: 'https://u:p@mcp.example.com' }, 'serverUrl'],
    ['more than 30 days', { personalKeys: { maxDays: 31 } }, 'personalKeys.maxDays'],
    ['zero days', { personalKeys: { maxDays: 0 } }, 'personalKeys.maxDays'],
    ['a name that is not a group', { allowedGroups: ['has space'] }, 'allowedGroups'],
    ['an empty group list', { allowedGroups: [] }, 'allowedGroups'],
    ['the retired org list', { allowedOrgs: 'all' }, 'allowedOrgs'],
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


describe('oauth (browser sign-in)', () => {
  it('is ON by default whenever MCP is on (owner D5), 30 days, protected actions for 12 h', () => {
    expect(defaultMcpSettings().oauth).toEqual({ enabled: true, maxDays: 30, protectedActions: 'window', protectedActionsHours: 12 })
    expect(parseMcpSettings(JSON.stringify({ enabled: true })).oauth.enabled).toBe(true)
  })

  it('takes a partial document, keeping the defaults for the rest', () => {
    const r = validateMcpSettings({ enabled: true, oauth: { enabled: false, protectedActionsHours: 2 } })
    expect(r).toMatchObject({ ok: true, value: { oauth: { enabled: false, maxDays: 30, protectedActions: 'window', protectedActionsHours: 2 } } })
  })

  it.each([
    [{ enabled: 'yes' }, 'oauth.enabled'],
    [{ maxDays: 31 }, 'oauth.maxDays'],
    [{ maxDays: 0 }, 'oauth.maxDays'],
    [{ protectedActions: 'always' }, 'oauth.protectedActions'],
    [{ protectedActionsHours: 721 }, 'oauth.protectedActionsHours'],
    [{ protectedActionsHours: 1.5 }, 'oauth.protectedActionsHours'],
  ])('refuses oauth %j', (oauth, field) => {
    const r = validateMcpSettings({ enabled: true, oauth })
    expect(r.ok).toBe(false)
    expect((r as { problems: { field: string }[] }).problems.map((p) => p.field)).toEqual([field])
  })

  it('refuses an oauth that is not an object', () => {
    expect(validateMcpSettings({ enabled: true, oauth: [] }).ok).toBe(false)
  })

  it('status offers browser sign-in only with an issuer configured and the switch on', async () => {
    const app = Fastify()
    installRouteAccess(app)
    app.addHook('onRequest', async (req: FastifyRequest) => { req.userContext = { email: 'ann@acme.io', id: 'u1', name: 'Ann' } })
    await app.register(mcpStatusRoutes, { prefix: '/api/mcp' })
    store({ enabled: true })
    expect((await app.inject({ method: 'GET', url: '/api/mcp/status' })).json().oauth).toEqual({ enabled: false })
    h.env.MCP_OAUTH_ISSUER = 'https://hydra.example.com/'
    expect((await app.inject({ method: 'GET', url: '/api/mcp/status' })).json().oauth).toEqual({ enabled: true })
    store({ enabled: true, oauth: { enabled: false } })
    expect((await app.inject({ method: 'GET', url: '/api/mcp/status' })).json().oauth).toEqual({ enabled: false })
    delete h.env.MCP_OAUTH_ISSUER
    await app.close()
  })
})

describe('allowedGroups', () => {
  it('lets in a holder of any listed group, or anybody with all', () => {
    const on = (allowedGroups: 'all' | string[]) => ({ ...defaultMcpSettings(), enabled: true, allowedGroups })
    expect(groupAllowed(on('all'), [])).toBe(true)
    expect(groupAllowed(on(['support', 'ops']), ['staff', 'ops'])).toBe(true)
    expect(groupAllowed(on(['support']), ['staff'])).toBe(false)
  })

  it('migrates a document saved before groups, once: all stays all, an org list becomes no group (closed)', async () => {
    store({ enabled: true, personalKeys: { maxDays: 7 }, allowedOrgs: 'all' })
    expect((await getMcpSettings()).allowedGroups).toBe('all')
    expect(JSON.parse(h.config[MCP_SETTINGS_KEY])).toEqual({ enabled: true, serverUrl: null, personalKeys: { maxDays: 7 }, allowedGroups: 'all', oauth: { enabled: true, maxDays: 30, protectedActions: 'window', protectedActionsHours: 12 } })
    store({ enabled: true, allowedOrgs: ['11111111-1111-1111-1111-111111111111'] })
    expect((await getMcpSettings()).allowedGroups).toEqual([])
    expect(JSON.parse(h.config[MCP_SETTINGS_KEY]).allowedOrgs).toBeUndefined()
  })
})

describe('routes', () => {
  let app: FastifyInstance
  beforeAll(async () => {
    app = Fastify()
    installRouteAccess(app)
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
    const res = await put({ enabled: false, serverUrl: 'https://mcp.example.com/mcp', personalKeys: { maxDays: 7 }, allowedGroups: 'all' })
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
    expect((await status()).json()).toEqual({ enabled: true, serverUrl: 'https://mcp.example.com/mcp', off: null, personalKeys: { maxDays: 7 }, allowed: true, oauth: { enabled: false } })
    store({ enabled: true, serverUrl: 'https://mcp.example.com/mcp', personalKeys: { maxDays: 7 }, allowedGroups: ['support'] })
    expect((await status()).json()).toMatchObject({ enabled: true, allowed: false })
    store({ enabled: true, serverUrl: 'https://mcp.example.com/mcp', personalKeys: { maxDays: 7 } })
    store({ enabled: false, serverUrl: 'https://mcp.example.com/mcp' })
    expect((await status()).json()).toMatchObject({ enabled: false, off: 'administrator' })
    h.env.DELEGATED_TOKENS_ENABLED = false
    expect((await status()).json()).toEqual({ enabled: false, serverUrl: null, off: 'deployment', personalKeys: null, allowed: null, oauth: { enabled: false } })
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
