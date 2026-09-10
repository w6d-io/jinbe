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

import { rbacOpalRoutes } from '../../../routes/rbac.routes.js'

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

// What is left here is `/bindings`, which the console reads. The org->service map and the OPAL
// datasource manifest tested alongside it are gone with the routes: their only caller was OPAL,
// which does not run in this namespace.
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

    it('fails closed to an empty full-shape dataset when Kratos is unavailable', async () => {
      mocks.getBindingsFromKratos.mockRejectedValueOnce(new Error('Kratos unreachable'))

      const reply = createMockReply()
      await handlerFor('/bindings')({} as FastifyRequest, reply)

      expect(reply._body).toEqual({
        emails: {},
        group_membership: {},
        user_organizations: {},
        user_organization_primary: {},
      })
    })
  })
})
