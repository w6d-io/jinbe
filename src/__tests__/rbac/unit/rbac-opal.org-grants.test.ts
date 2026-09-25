import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

// J-1: org_grants and route org_param reach OPA through the OPAL routes, behind the OPAL token.

const mocks = vi.hoisted(() => ({
  getAll: vi.fn(),
  getServices: vi.fn(),
  getRouteMap: vi.fn(),
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

describe('OPAL routes — org_grants', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.getServices.mockResolvedValue([])
    mocks.getRouteMap.mockResolvedValue(null)
  })

  it('stay behind the OPAL client token', async () => {
    const { fastify } = await routes()
    expect(fastify.addHook).toHaveBeenCalledWith('onRequest', requireOpalClient)
  })

  it('GET /opal/org_grants serves the whole map', async () => {
    const map = { acme: { 'bob@acme.test': ['fleet-viewers'] } }
    mocks.getAll.mockResolvedValueOnce(map)
    const { call } = await routes()
    const reply = await call('/opal/org_grants')
    expect(reply._status).toBe(200)
    expect(reply._body).toEqual(map)
  })

  it('GET /opal/org_grants serves an empty map when nothing was granted', async () => {
    mocks.getAll.mockResolvedValueOnce({})
    const { call } = await routes()
    expect((await call('/opal/org_grants'))._body).toEqual({})
  })

  it('GET /opal/org_grants answers 503 on a store error — never an empty or partial map', async () => {
    mocks.getAll.mockRejectedValueOnce(new Error('ECONNREFUSED'))
    const { call } = await routes()
    const reply = await call('/opal/org_grants')
    expect(reply._status).toBe(503)
    expect(reply._body).not.toEqual({})
    expect(reply._body).toHaveProperty('error', 'Service Unavailable')
  })

  it('the datasource manifest fetches /org_grants with the bearer token', async () => {
    const { call } = await routes()
    const { entries } = (await call('/opal-datasource'))._body as {
      entries: Array<{ url: string; dst_path: string; config: { headers: Record<string, string> } }>
    }
    const entry = entries.find((e) => e.dst_path === '/org_grants')
    expect(entry).toBeDefined()
    expect(entry!.url).toBe('http://auth-jinbe:8080/api/admin/rbac/opal/org_grants')
    expect(entry!.config.headers.Authorization).toBe(`Bearer ${'t'.repeat(64)}`)
  })

  it('GET /opal/route_map/:service passes org_param through to OPA', async () => {
    const rules = [{ method: 'GET', path: '/api/fleet/orgs/:orgId/x', permission: 'fleet:read', org_param: 'orgId' }]
    mocks.getRouteMap.mockResolvedValueOnce({ rules })
    const { call } = await routes()
    expect((await call('/opal/route_map/:service', { service: 'fleet' }))._body).toEqual({ rules })
  })
})
