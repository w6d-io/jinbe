import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

// ---------------------------------------------------------------------------
// Mocks — the OPAL public routes call the Redis repo, the Kratos service, and
// (for /bindings) the RBAC service. We stub all three so the handlers run in
// isolation without touching Redis or Kratos.
// ---------------------------------------------------------------------------
const mocks = vi.hoisted(() => ({
  getOrgServiceMap: vi.fn(),
  getServices: vi.fn(),
  getRouteMap: vi.fn(),
  getGroups: vi.fn(),
  getRoles: vi.fn(),
  getBindingsFromKratos: vi.fn(),
}))

vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getOrgServiceMap: mocks.getOrgServiceMap,
    getServices: mocks.getServices,
    getRouteMap: mocks.getRouteMap,
    getGroups: mocks.getGroups,
    getRoles: mocks.getRoles,
  },
}))

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getAllIdentitiesWithGroups: vi.fn(),
    getAllIdentitiesWithBindings: vi.fn(),
  },
  KratosApiError: class KratosApiError extends Error {},
}))

vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: {
    getBindingsFromKratos: mocks.getBindingsFromKratos,
  },
}))

vi.mock('../../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../config/env.js')>()
  return { ...real, env: { ...real.env, OPAL_CLIENT_TOKEN: 't'.repeat(64), JINBE_INTERNAL_URL: 'http://auth-jinbe:8080' } }
})

import { rbacOpalRoutes } from '../../../routes/rbac.routes.js'
import { requireOpalClient } from '../../../middleware/require-opal-client.js'

// A minimal fastify stand-in that records registered routes so we can invoke
// each handler directly. Supports both `get(path, handler)` and
// `get(path, opts, handler)` call shapes.
type Handler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
function createMockFastify() {
  const routes: Array<{ method: string; path: string; handler: Handler }> = []
  const record =
    (method: string) =>
    (path: string, a?: unknown, b?: unknown) => {
      const handler = (typeof a === 'function' ? a : b) as Handler
      routes.push({ method, path, handler })
    }
  return {
    registeredRoutes: routes,
    get: vi.fn(record('GET')),
    post: vi.fn(record('POST')),
    put: vi.fn(record('PUT')),
    delete: vi.fn(record('DELETE')),
    patch: vi.fn(record('PATCH')),
    addHook: vi.fn(),
  } as unknown as FastifyInstance & {
    registeredRoutes: Array<{ method: string; path: string; handler: Handler }>
  }
}

function createMockReply() {
  const reply: { _status: number; _body: unknown; status: unknown; send: unknown } = {
    _status: 200,
    _body: undefined,
    status: vi.fn(function (this: typeof reply, s: number) {
      this._status = s
      return this
    }),
    send: vi.fn(function (this: typeof reply, b: unknown) {
      this._body = b
      return this
    }),
  }
  return reply as unknown as FastifyReply & { _status: number; _body: unknown }
}

// OPAL is the only caller of these routes; the console reads none of them.
describe('rbacOpalRoutes — /bindings', () => {
  let fastify: ReturnType<typeof createMockFastify>

  const handlerFor = (path: string): Handler => {
    const route = fastify.registeredRoutes.find((r) => r.method === 'GET' && r.path === path)
    if (!route) throw new Error(`No GET handler registered for ${path}`)
    return route.handler
  }

  beforeEach(async () => {
    vi.clearAllMocks()
    fastify = createMockFastify()
    await rbacOpalRoutes(fastify)
  })

  describe('GET /bindings', () => {
    it('returns the full bindings shape including org membership', async () => {
      const bindings = {
        emails: {},
        group_membership: { 'user@example.com': ['users'] },
        user_organizations: { 'user@example.com': ['org-1', 'org-2'] },
        user_organization_primary: { 'user@example.com': 'org-1' },
      }
      mocks.getBindingsFromKratos.mockResolvedValueOnce(bindings)

      const reply = createMockReply()
      await handlerFor('/bindings')({} as FastifyRequest, reply)

      expect(reply._body).toEqual(bindings)
    })

    it('answers 503 when Kratos is unavailable, so OPAL keeps the last good bindings', async () => {
      mocks.getBindingsFromKratos.mockRejectedValueOnce(new Error('Kratos unreachable'))

      const reply = createMockReply()
      await handlerFor('/bindings')({ log: { error: vi.fn() } } as unknown as FastifyRequest, reply)

      // An empty dataset here would replace OPA's bindings and deny everyone, super_admin included.
      expect(reply._status).toBe(503)
      expect(reply._body).not.toHaveProperty('group_membership')
    })
  })
})

describe('rbacOpalRoutes — OPAL client only', () => {
  it('guards every route with the OPAL client token', async () => {
    const fastify = createMockFastify()
    await rbacOpalRoutes(fastify)
    expect(fastify.addHook).toHaveBeenCalledWith('onRequest', requireOpalClient)
  })

  it('tells OPAL to send the token on every data fetch', async () => {
    mocks.getServices.mockResolvedValueOnce(['jinbe'])
    mocks.getRouteMap.mockResolvedValue({ rules: [{ path: '/x' }] })
    const fastify = createMockFastify()
    await rbacOpalRoutes(fastify)
    const manifest = fastify.registeredRoutes.find((r) => r.path === '/opal-datasource')!
    const reply = createMockReply()
    await manifest.handler({} as FastifyRequest, reply)

    const { entries } = reply._body as { entries: Array<{ config: { headers: Record<string, string> } }> }
    expect(entries.length).toBeGreaterThan(0)
    for (const entry of entries) {
      expect(entry.config.headers.Authorization).toBe(`Bearer ${'t'.repeat(64)}`)
    }
  })
})
