import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

// Integration-style: exercise the REAL /bindings handler → real rbacService →
// real kratosService → mocked global.fetch. Only Redis is stubbed (the path
// under test doesn't touch it). A Kratos call that rejects (as an aborted /
// timed-out request does) must answer 503: OPAL then keeps the bindings OPA already holds,
// where an empty dataset would have denied everyone until the next fetch.

const { redisModule } = vi.hoisted(() => {
  const stub = {
    get: vi.fn().mockResolvedValue(null),
    set: vi.fn().mockResolvedValue('OK'),
    hgetall: vi.fn().mockResolvedValue({}),
    smembers: vi.fn().mockResolvedValue([]),
  }
  return {
    redisModule: {
      redisClientService: { getClient: () => stub, isHealthy: vi.fn().mockResolvedValue(true), disconnect: vi.fn().mockResolvedValue(undefined), isConnected: true },
      getRedisClient: () => stub,
    },
  }
})

vi.mock('../../../services/redis-client.service.js', () => redisModule)

import { rbacOpalRoutes } from '../../../routes/rbac-opal.routes.js'
import { kratosService } from '../../../services/kratos.service.js'

type Handler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
function createMockFastify() {
  const routes: Array<{ method: string; path: string; handler: Handler }> = []
  const record =
    (method: string) =>
    (path: string, a?: unknown, b?: unknown) => {
      routes.push({ method, path, handler: (typeof a === 'function' ? a : b) as Handler })
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
  const reply = {
    _status: 200,
    _body: undefined as unknown,
    status: vi.fn(function (this: typeof reply, s: number) { this._status = s; return this }),
    send: vi.fn(function (this: typeof reply, b: unknown) { this._body = b; return this }),
  }
  return reply as unknown as FastifyReply & { _status: number; _body: unknown }
}

describe('GET /bindings — 503 on aborted/timed-out Kratos', () => {
  let fastify: ReturnType<typeof createMockFastify>

  beforeEach(async () => {
    vi.clearAllMocks()
    // Clear the singleton directory cache so each test forces a fresh scan.
    kratosService.invalidateGroupsCache()
    fastify = createMockFastify()
    await rbacOpalRoutes(fastify)
  })

  it('answers 503, not an empty dataset, when the Kratos fetch rejects (abort)', async () => {
    // Reject exactly as node fetch does when its AbortSignal fires.
    global.fetch = vi.fn().mockRejectedValue(new Error('The operation was aborted'))

    const handler = fastify.registeredRoutes.find(
      (r) => r.method === 'GET' && r.path === '/bindings'
    )!.handler
    const reply = createMockReply()
    await handler({ log: { error: vi.fn() } } as unknown as FastifyRequest, reply)

    expect(reply._status).toBe(503)
    expect(reply._body).not.toHaveProperty('group_membership')
  })
})
