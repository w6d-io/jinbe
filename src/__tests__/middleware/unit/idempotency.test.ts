import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import { readFileSync } from 'node:fs'

// Idempotency-Key on POST/PUT/PATCH (middleware/idempotency.ts): a replay answers what the first
// request was answered; the same key with another body is 422; a key still running is 409; a 5xx is
// not kept, so the write can be retried.

const r = vi.hoisted(() => ({ store: new Map<string, string>() }))
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    set: async (k: string, v: string, ...args: unknown[]) => {
      if (args.includes('NX') && r.store.has(k)) return null
      r.store.set(k, v)
      return 'OK'
    },
    get: async (k: string) => r.store.get(k) ?? null,
    del: async (k: string) => (r.store.delete(k) ? 1 : 0),
  }),
}))

import { registerIdempotency } from '../../../middleware/idempotency.js'

let app: FastifyInstance
let calls = 0
let status = 201
let hold: Promise<void> | null = null

beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request) => {
    const who = String(request.headers['x-user'] ?? 'alice')
    request.userContext = { id: who, email: `${who}@x.test`, name: who } as never
  })
  registerIdempotency(app)
  app.post('/things', async (_request, reply) => {
    calls += 1
    if (hold) await hold
    return reply.status(status).send({ n: calls })
  })
  app.get('/things', async () => ({ n: calls }))
  await app.ready()
})
afterAll(() => app.close())
beforeEach(() => {
  r.store.clear()
  calls = 0
  status = 201
  hold = null
})

const post = (payload: unknown, key?: string, user = 'alice') =>
  app.inject({ method: 'POST', url: '/things', payload: payload as object, headers: { ...(key ? { 'idempotency-key': key } : {}), 'x-user': user } })

describe('Idempotency-Key', () => {
  it('replays the first answer, with its status, and does the work once', async () => {
    const first = await post({ a: 1 }, 'key-00000001')
    const again = await post({ a: 1 }, 'key-00000001')
    expect(first.statusCode).toBe(201)
    expect(again.statusCode).toBe(201)
    expect(again.json()).toEqual({ n: 1 })
    expect(again.headers['idempotent-replayed']).toBe('true')
    expect(calls).toBe(1)
  })

  it('treats a body with the same fields in another order as the same request', async () => {
    await post({ a: 1, b: 2 }, 'key-00000002')
    expect((await post({ b: 2, a: 1 }, 'key-00000002')).statusCode).toBe(201)
    expect(calls).toBe(1)
  })

  it('refuses the same key with a different body: 422 idempotency_key_reused', async () => {
    await post({ a: 1 }, 'key-00000003')
    const res = await post({ a: 2 }, 'key-00000003')
    expect(res.statusCode).toBe(422)
    expect(res.json().error).toBe('idempotency_key_reused')
    expect(calls).toBe(1)
  })

  it('answers 409 idempotency_in_progress while the first request runs', async () => {
    let release!: () => void
    hold = new Promise((res) => { release = res })
    const first = post({ a: 1 }, 'key-00000004')
    await new Promise((res) => setTimeout(res, 20))
    const second = await post({ a: 1 }, 'key-00000004')
    expect(second.statusCode).toBe(409)
    expect(second.json().error).toBe('idempotency_in_progress')
    release()
    expect((await first).statusCode).toBe(201)
  })

  it('does not keep a 5xx: the retry runs again', async () => {
    status = 503
    expect((await post({ a: 1 }, 'key-00000005')).statusCode).toBe(503)
    status = 201
    const retry = await post({ a: 1 }, 'key-00000005')
    expect(retry.statusCode).toBe(201)
    expect(retry.headers['idempotent-replayed']).toBeUndefined()
    expect(calls).toBe(2)
  })

  it('keeps a 4xx answer (the same request would be refused the same way)', async () => {
    status = 409
    await post({ a: 1 }, 'key-00000006')
    status = 201
    expect((await post({ a: 1 }, 'key-00000006')).statusCode).toBe(409)
    expect(calls).toBe(1)
  })

  it('scopes a key to its caller: somebody else sending the same key is a new request', async () => {
    await post({ a: 1 }, 'key-00000007', 'alice')
    const bob = await post({ a: 1 }, 'key-00000007', 'bob')
    expect(bob.headers['idempotent-replayed']).toBeUndefined()
    expect(calls).toBe(2)
  })

  it('leaves a request without the header, and a GET, untouched', async () => {
    await post({ a: 1 })
    await post({ a: 1 })
    expect(calls).toBe(2)
    await app.inject({ method: 'GET', url: '/things', headers: { 'idempotency-key': 'key-00000008' } })
    expect(r.store.size).toBe(0)
  })

  it('refuses a malformed key: 400', async () => {
    expect((await post({ a: 1 }, 'bad key!')).statusCode).toBe(400)
    expect(calls).toBe(0)
  })

  it('is registered on the server, after the delegation gate', () => {
    const server = readFileSync(new URL('../../../server.ts', import.meta.url), 'utf8')
    const gate = server.indexOf("addHook('preHandler', delegationGate)")
    const idem = server.indexOf('registerIdempotency(fastify)')
    expect(gate).toBeGreaterThan(0)
    expect(idem).toBeGreaterThan(gate)
  })
})
