import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

// S-4a: data.site_login reaches OPA through the OPAL routes, behind the OPAL token.

const mocks = vi.hoisted(() => ({
  getAll: vi.fn(),
  getServices: vi.fn(),
  getRouteMap: vi.fn(),
  siteLogin: vi.fn(),
}))

vi.mock('../../../services/org-grants.repository.js', () => ({
  orgGrantsRepository: { getAll: mocks.getAll },
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getServices: mocks.getServices,
    getRouteMap: mocks.getRouteMap,
    getGroups: vi.fn(),
    getRoles: vi.fn(),
    getOrgServiceMap: vi.fn(),
    getOrgAdminMap: vi.fn(),
  },
}))
vi.mock('../../../sites/login-store.js', () => ({ siteLoginStore: { getAll: mocks.siteLogin } }))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { getBindingsFromKratos: vi.fn() } }))
vi.mock('../../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../config/env.js')>()
  return { ...real, env: { ...real.env, OPAL_CLIENT_TOKEN: 't'.repeat(64), JINBE_INTERNAL_URL: 'http://auth-jinbe:8080' } }
})

import { rbacOpalRoutes } from '../../../routes/rbac-opal.routes.js'
import { requireOpalClient } from '../../../middleware/require-opal-client.js'

type Handler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>

async function routes() {
  const registered: Array<{ path: string; handler: Handler }> = []
  const fastify = {
    get: vi.fn((path: string, a: unknown, b?: unknown) => {
      registered.push({ path, handler: (typeof a === 'function' ? a : b) as Handler })
    }),
    addHook: vi.fn(),
  } as unknown as FastifyInstance
  await rbacOpalRoutes(fastify)
  const call = async (path: string, params: Record<string, string> = {}) => {
    const reply = {
      _status: 200,
      _body: undefined as unknown,
      status(s: number) { this._status = s; return this },
      send(b: unknown) { this._body = b; return this },
    }
    const route = registered.find((r) => r.path === path)
    if (!route) throw new Error(`no route ${path}`)
    await route.handler({ params, log: { error: vi.fn() } } as unknown as FastifyRequest, reply as unknown as FastifyReply)
    return reply
  }
  return { fastify, call }
}

describe('OPAL routes — site_login', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.getServices.mockResolvedValue([])
    mocks.getRouteMap.mockResolvedValue(null)
  })

  it('GET /opal/site_login serves every site entry', async () => {
    const map = { payroll: { min_aal: 'aal2', scope: 'writes', routes: [], clients: 'exempt' } }
    mocks.siteLogin.mockResolvedValueOnce(map)
    const { call } = await routes()
    const reply = await call('/opal/site_login')
    expect(reply._status).toBe(200)
    expect(reply._body).toEqual(map)
  })

  it('GET /opal/site_login serves an empty map when no site asks for 2FA', async () => {
    mocks.siteLogin.mockResolvedValueOnce({})
    const { call } = await routes()
    expect((await call('/opal/site_login'))._body).toEqual({})
  })

  it('GET /opal/site_login answers 503 on a store error', async () => {
    mocks.siteLogin.mockRejectedValueOnce(new Error('ECONNREFUSED'))
    const { call } = await routes()
    const reply = await call('/opal/site_login')
    expect(reply._status).toBe(503)
    expect(reply._body).toHaveProperty('error', 'Service Unavailable')
  })

  it('the datasource manifest fetches /site_login with the bearer token', async () => {
    const { call } = await routes()
    const { entries } = (await call('/opal-datasource'))._body as {
      entries: Array<{ url: string; dst_path: string; config: { headers: Record<string, string> } }>
    }
    const entry = entries.find((e) => e.dst_path === '/site_login')
    expect(entry!.url).toBe('http://auth-jinbe:8080/api/admin/rbac/opal/site_login')
    expect(entry!.config.headers.Authorization).toBe(`Bearer ${'t'.repeat(64)}`)
  })
})
