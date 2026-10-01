import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { installRouteAccess } from '../../../policy/route-access.js'
import Fastify, { type FastifyInstance } from 'fastify'
import rateLimit from '@fastify/rate-limit'

// GET /api/admin/users/lookup: users:read, enforced by jinbe itself through OPA (the gateway is not
// the only way in), and rate limited per caller.

const s = vi.hoisted(() => ({ rights: {} as Record<string, string[]>, lookups: [] as Array<[string, unknown]> }))

vi.mock('../../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../config/env.js')>()
  const over: Record<string, string> = { OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret' }
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in over ? over[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../../services/user-lookup.service.js', () => ({
  LOOKUP_MAX: 10,
  lookupUsers: vi.fn(async (q: string, limit?: number) => {
    s.lookups.push([q, limit])
    return { match: 'email', data: [{ id: 'u1', email: q, name: null, active: true, groups: [], organizations: [], mfa: false }] }
  }),
}))
vi.mock('../../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { userManagementRoutes } from '../../../routes/user-management.routes.js'
import { clearAuthzCache } from '../../../authz/opa.js'

let app: FastifyInstance
beforeAll(async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.startsWith('http://opal-client:8181/v1/data/rbac/user_info')) {
      const body = JSON.parse(init!.body as string) as { input: Record<string, unknown> }
      const who = String(body.input.email).split('@')[0]
      return Response.json({ result: { email: body.input.email, groups: [], roles: [], permissions: s.rights[who] ?? [] } })
    }
    return new Response('{}', { status: 404 })
  }))
  app = Fastify()
  installRouteAccess(app)
  await app.register(rateLimit, { global: true, max: 10_000, timeWindow: '1 minute' })
  app.addHook('onRequest', async (request) => {
    const who = request.headers['x-test-user'] as string | undefined
    if (who) request.userContext = { id: who, email: `${who}@example.com`, name: who } as never
  })
  await app.register(async (api) => {
    await api.register(userManagementRoutes, { prefix: '/admin' })
  }, { prefix: '/api' })
  await app.ready()
})
afterAll(async () => {
  vi.unstubAllGlobals()
  await app.close()
})
beforeEach(() => {
  s.rights = { support: ['users:read'], nobody: [], admin: ['users:read', 'users:create'], legacy: ['admin:read', 'admin:write'] }
  s.lookups = []
  clearAuthzCache()
})

const lookup = (who: string, qs: string) =>
  app.inject({ method: 'GET', url: `/api/admin/users/lookup?${qs}`, headers: { 'x-test-user': who } })

describe('GET /api/admin/users/lookup', () => {
  it('answers a caller holding users:read', async () => {
    const res = await lookup('support', 'q=alice%40example.com&limit=5')
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ match: 'email', data: [{ email: 'alice@example.com' }] })
    expect(s.lookups).toEqual([['alice@example.com', 5]])
  })

  it('a retired coarse name grants nothing: exact match only', async () => {
    expect((await lookup('legacy', 'q=ali')).statusCode).toBe(403)
    expect((await lookup('admin', 'q=ali')).statusCode).toBe(200)
  })

  it('refuses a caller without users:read, before asking the directory', async () => {
    const res = await lookup('nobody', 'q=ali')
    expect(res.statusCode).toBe(403)
    expect(s.lookups).toEqual([])
  })

  it('refuses an anonymous caller', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/admin/users/lookup?q=ali' })
    expect(res.statusCode).toBe(401)
  })

  it('refuses an empty query or a limit above ten', async () => {
    expect((await lookup('support', 'q=')).statusCode).toBe(400)
    expect((await lookup('support', 'q=ali&limit=50')).statusCode).toBe(400)
  })

  it('limits each caller to 120 lookups a minute, separately', async () => {
    let last = 0
    for (let i = 0; i < 121; i++) last = (await lookup('admin', `q=a${i}`)).statusCode
    expect(last).toBe(429)
    expect((await lookup('support', 'q=ali')).statusCode).toBe(200)
  })
})
