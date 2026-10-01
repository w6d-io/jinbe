import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest } from 'fastify'

// Key views: last_used_at from one shared Redis hash (written at most once a minute per key, read under
// a deadline, never failing a request), and created_by_email only for the creator themself or a caller
// who may see users.

const s = vi.hoisted(() => ({
  redis: { hset: vi.fn(async () => 1), hdel: vi.fn(async () => 1), hmget: vi.fn(async () => [] as (string | null)[]) },
  rights: vi.fn(async () => ({ permissions: [] as string[] })),
  byIds: vi.fn(async () => new Map<string, { id: string; traits: Record<string, unknown> }>()),
}))

vi.mock('../../../services/redis-client.service.js', () => ({ getRedisClient: () => s.redis }))
vi.mock('../../../authz/opa.js', () => ({ rights: s.rights }))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: { getIdentitiesByIds: s.byIds } }))

import { LAST_USED_KEY, forgetApiKeyUse, lastUsedOf, resetApiKeyUseThrottle, touchApiKeyUse } from '../../../services/api-key-last-used.js'
import { decorateKeyViews } from '../../../services/api-key-views.js'
import type { ApiKeyView } from '../../../schemas/api-key.schema.js'

const NOW = Date.parse('2026-09-28T12:00:00Z')
const ME = '11111111-1111-1111-1111-111111111111'
const OTHER = '22222222-2222-2222-2222-222222222222'

beforeEach(() => {
  resetApiKeyUseThrottle()
  Object.values(s.redis).forEach((f) => f.mockClear())
  s.redis.hmget.mockReset().mockResolvedValue([])
  s.rights.mockReset().mockResolvedValue({ permissions: [] })
  s.byIds.mockReset().mockResolvedValue(new Map())
})

describe('touchApiKeyUse', () => {
  it('writes the hash at most once a minute per key', () => {
    touchApiKeyUse('k1', NOW)
    touchApiKeyUse('k1', NOW + 30_000)
    touchApiKeyUse('k2', NOW + 30_000)
    touchApiKeyUse('k1', NOW + 60_000)
    expect(s.redis.hset.mock.calls).toEqual([
      [LAST_USED_KEY, 'k1', String(NOW)],
      [LAST_USED_KEY, 'k2', String(NOW + 30_000)],
      [LAST_USED_KEY, 'k1', String(NOW + 60_000)],
    ])
  })

  it('never throws, whether Redis rejects or cannot even be reached', () => {
    s.redis.hset.mockRejectedValueOnce(new Error('down'))
    expect(() => touchApiKeyUse('k1', NOW)).not.toThrow()
    s.redis.hset.mockImplementationOnce(() => { throw new Error('no client') })
    expect(() => touchApiKeyUse('k2', NOW)).not.toThrow()
  })

  it('forgets a revoked key', () => {
    touchApiKeyUse('k1', NOW)
    forgetApiKeyUse('k1')
    expect(s.redis.hdel).toHaveBeenCalledWith(LAST_USED_KEY, 'k1')
    touchApiKeyUse('k1', NOW + 1)
    expect(s.redis.hset).toHaveBeenCalledTimes(2)
  })
})

describe('lastUsedOf', () => {
  it('reads every key in one HMGET, absent when never seen', async () => {
    s.redis.hmget.mockResolvedValue([String(NOW), null])
    const out = await lastUsedOf(['k1', 'k2', 'k1'])
    expect(s.redis.hmget).toHaveBeenCalledWith(LAST_USED_KEY, 'k1', 'k2')
    expect([...out]).toEqual([['k1', '2026-09-28T12:00:00.000Z']])
  })

  it('answers "unknown" instead of failing or waiting on Redis', async () => {
    s.redis.hmget.mockRejectedValueOnce(new Error('down'))
    expect((await lastUsedOf(['k1'])).size).toBe(0)
    s.redis.hmget.mockImplementationOnce(() => new Promise(() => {}))
    const started = Date.now()
    expect((await lastUsedOf(['k1'])).size).toBe(0)
    expect(Date.now() - started).toBeLessThan(1000)
  })
})

describe('decorateKeyViews', () => {
  const view = (client_id: string, created_by: string | null): ApiKeyView => ({
    client_id, organization_id: 'acme', label: client_id, scopes: [], created_by,
    created_at: null, expires_at: null, last_used_at: null, created_by_email: null,
  })
  const request = (over: Partial<FastifyRequest> = {}) =>
    ({ userContext: { id: ME, email: 'me@acme.io', name: 'Me' }, log: { warn: vi.fn() }, ...over }) as unknown as FastifyRequest

  it("adds last use and the caller's own address, without asking Kratos for it", async () => {
    s.redis.hmget.mockResolvedValue([String(NOW), null])
    const out = await decorateKeyViews(request(), [view('k1', ME), view('k2', OTHER)])
    expect(out.map((v) => [v.last_used_at, v.created_by_email])).toEqual([['2026-09-28T12:00:00.000Z', 'me@acme.io'], [null, null]])
    expect(s.byIds).not.toHaveBeenCalled()
  })

  it("shows somebody else's address only to a caller holding users:read, in one batch", async () => {
    s.rights.mockResolvedValue({ permissions: ['users:read'] })
    s.byIds.mockResolvedValue(new Map([[OTHER, { id: OTHER, traits: { email: 'bob@acme.io' } }]]))
    const out = await decorateKeyViews(request(), [view('k1', OTHER), view('k2', OTHER), view('k3', 'not-an-id'), view('k4', null)])
    expect(s.byIds).toHaveBeenCalledWith([OTHER])
    expect(out.map((v) => v.created_by_email)).toEqual(['bob@acme.io', 'bob@acme.io', null, null])
  })

  it('reuses the rights already read for this request', async () => {
    s.byIds.mockResolvedValue(new Map([[OTHER, { id: OTHER, traits: { email: 'bob@acme.io' } }]]))
    const req = request({ rbacInfo: { email: 'me@acme.io', groups: [], roles: [], permissions: ['users:read'] } } as Partial<FastifyRequest>)
    expect((await decorateKeyViews(req, [view('k1', OTHER)]))[0].created_by_email).toBe('bob@acme.io')
    expect(s.rights).not.toHaveBeenCalled()
  })

  it('leaves the address null when rights or Kratos cannot be read, and still answers', async () => {
    s.rights.mockRejectedValueOnce(new Error('opa down'))
    expect((await decorateKeyViews(request(), [view('k1', OTHER)]))[0].created_by_email).toBeNull()
    s.rights.mockResolvedValue({ permissions: ['users:read'] })
    s.byIds.mockRejectedValueOnce(new Error('kratos down'))
    expect((await decorateKeyViews(request(), [view('k1', OTHER)]))[0].created_by_email).toBeNull()
  })
})
