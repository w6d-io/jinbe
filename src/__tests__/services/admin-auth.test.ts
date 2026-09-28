import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Writes take a per-identity Redis lock; passthrough so the fake admin API is all this needs.
vi.mock('../../services/redis-lock.js', () => ({ withRedisLock: (_name: string, fn: () => unknown) => fn() }))

import { env } from '../../config/index.js'
import { adminAuthHeaders, redactUrl } from '../../services/admin-auth.js'
import { KratosService } from '../../services/kratos.service.js'
import { HydraService, HydraUnavailableError } from '../../services/hydra.service.js'
import { waitForKratos } from '../../bootstrap/wait-deps.js'
import { kratosReady } from '../../home/sources.js'

/**
 * Every call jinbe makes to the Kratos and Hydra admin APIs carries `Authorization: Bearer <token>`
 * when a token is configured (the chart's admin sidecar refuses anything else), none without one,
 * and the public ports never see it.
 */

const TOKEN = 'k'.repeat(64)
const HTOKEN = 'h'.repeat(64)

type Call = { url: string; auth: string | null }
const calls: Call[] = []

function authOf(init: RequestInit = {}): string | null {
  const h = init.headers
  if (!h) return null
  if (h instanceof Headers) return h.get('authorization')
  const rec = h as Record<string, string>
  return rec.Authorization ?? rec.authorization ?? null
}

function reply(body: unknown, status = 200) {
  return { ok: status < 400, status, statusText: String(status), json: async () => body, text: async () => '', headers: new Headers() }
}

const fetchMock = vi.fn(async (url: string | URL, init: RequestInit = {}) => {
  const u = String(url)
  calls.push({ url: u, auth: authOf(init) })
  if (u.includes('/self-service/recovery/api')) return reply({ id: 'flow-1' })
  if (u.includes('/self-service/recovery?flow=')) return reply({ continue_with: [] })
  if (u.includes('/admin/identities/')) return reply({ id: 'i1', traits: { email: 'a@b.io' }, state: 'active', schema_id: 'default' })
  if (u.includes('/admin/identities')) return reply([])
  if (u.includes('/admin/oauth2/introspect')) return reply({ active: false })
  if (u.includes('/oauth2/token')) return reply({ access_token: 'at', expires_in: 60 })
  if (u.includes('/admin/clients')) return reply([])
  if (u.includes('/health/ready')) return reply({ status: 'ok' })
  return reply({}, 404)
})

const saved = { k: env.KRATOS_ADMIN_TOKEN, h: env.HYDRA_ADMIN_TOKEN }

beforeEach(() => {
  calls.length = 0
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  vi.unstubAllGlobals()
  env.KRATOS_ADMIN_TOKEN = saved.k
  env.HYDRA_ADMIN_TOKEN = saved.h
})

describe('adminAuthHeaders / redactUrl', () => {
  it('a token becomes a bearer header; no token, no header', () => {
    expect(adminAuthHeaders(TOKEN)).toEqual({ Authorization: `Bearer ${TOKEN}` })
    expect(adminAuthHeaders(undefined)).toEqual({})
    expect(adminAuthHeaders('')).toEqual({})
  })

  it('a URL in a log keeps scheme, host and path only', () => {
    expect(redactUrl('http://user:s3cret@kratos-admin:80/health/ready?token=x')).toBe('http://kratos-admin/health/ready')
    expect(redactUrl('http://auth-hydra-admin:4445')).toBe('http://auth-hydra-admin:4445')
    expect(redactUrl('not a url s3cret')).toBe('[invalid url]')
  })
})

describe('Kratos admin calls', () => {
  it('every admin call carries the token, the public recovery flow does not', async () => {
    env.KRATOS_ADMIN_TOKEN = TOKEN
    const k = new KratosService()
    await k.getIdentity('i1')
    await k.listIdentities(10)
    await k.listIdentitiesByIdentifierPrefix('a@', 5)
    await k.deleteIdentity('i1')
    const admin = calls.filter((c) => c.url.startsWith(env.KRATOS_ADMIN_URL))
    expect(admin.length).toBeGreaterThanOrEqual(4)
    expect(admin.every((c) => c.auth === `Bearer ${TOKEN}`)).toBe(true)

    calls.length = 0
    await k.sendRecoveryEmail('i1')
    const pub = calls.filter((c) => c.url.startsWith(env.KRATOS_PUBLIC_URL))
    expect(pub).toHaveLength(2)
    expect(pub.every((c) => c.auth === null)).toBe(true)
    expect(calls.filter((c) => c.url.startsWith(env.KRATOS_ADMIN_URL)).every((c) => c.auth === `Bearer ${TOKEN}`)).toBe(true)
  })

  it('without a token no Authorization header is sent', async () => {
    env.KRATOS_ADMIN_TOKEN = undefined
    const k = new KratosService()
    await k.getIdentity('i1')
    await k.listIdentities(10)
    expect(calls.length).toBe(2)
    expect(calls.every((c) => c.auth === null)).toBe(true)
  })

  it('the bootstrap wait and the Home readiness probe send it too, and log no credentials', async () => {
    env.KRATOS_ADMIN_TOKEN = TOKEN
    const logger = { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() }
    await waitForKratos({ url: 'http://u:pw@kratos-admin:80/', token: TOKEN, logger: logger as never, timeoutMs: 1000 })
    expect(await kratosReady(1000)).toBe('ok')
    expect(calls.map((c) => c.auth)).toEqual([`Bearer ${TOKEN}`, `Bearer ${TOKEN}`])
    expect(JSON.stringify(logger.info.mock.calls)).not.toMatch(/pw|u:|k{64}/)
  })
})

describe('Hydra admin calls', () => {
  it('client management, listing and introspection carry the token; the token endpoint uses the client secret', async () => {
    env.HYDRA_ADMIN_TOKEN = HTOKEN
    const h = new HydraService()
    await h.listClientsByOwner('org-1')
    await h.listAllClients()
    await h.introspect('opaque')
    await h.deleteClient('c1').catch(() => undefined)
    const admin = calls.filter((c) => c.url.startsWith(env.HYDRA_ADMIN_URL))
    expect(admin).toHaveLength(4)
    expect(admin.every((c) => c.auth === `Bearer ${HTOKEN}`)).toBe(true)

    calls.length = 0
    await h.clientCredentialsToken('c1', 'secret', ['read'])
    expect(calls[0].auth).toMatch(/^Basic /)
  })

  it('an unreachable admin API is named without credentials', async () => {
    const err = new HydraUnavailableError('http://svc:pw@auth-hydra-admin:4445', new Error('ECONNREFUSED'))
    expect(err.message).not.toContain('pw')
    expect(err.url).toBe('http://auth-hydra-admin:4445')
  })
})
