import { beforeEach, describe, expect, it, vi } from 'vitest'

// The grant store: the cookie value is never kept (its hash is the key), one grant per administrator
// session, found by the cookie or by the session, gone by TTL, by Stop or by a newer grant.

const h = vi.hoisted(() => ({ redis: new Map<string, { v: string; ttl?: number }>() }))

vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    get: async (k: string) => h.redis.get(k)?.v ?? null,
    set: async (k: string, v: string, _ex?: string, ttl?: number) => { h.redis.set(k, { v, ttl }); return 'OK' },
    del: async (...keys: string[]) => keys.filter((k) => h.redis.delete(k)).length,
  }),
}))

import { hashToken, impersonationStore, type NewGrant } from '../../impersonation/store.js'

const NOW = Date.parse('2026-11-10T10:00:00.000Z')
const input = (over: Partial<NewGrant> = {}): NewGrant => ({
  adminId: 'admin-1',
  adminEmail: 'ada@example.com',
  adminSessionId: 'sess-1',
  targetId: 'user-1',
  targetEmail: 'bob@example.com',
  targetName: 'Bob',
  reason: 'Ticket 4821: cannot see invoices',
  ...over,
})

beforeEach(() => h.redis.clear())

describe('impersonation grant store', () => {
  it('starts a grant: an opaque token of at least 32 bytes, stored only as its hash, with the lifetime as TTL', async () => {
    const { grant, token, replaced } = await impersonationStore.start(input(), 600, NOW)
    expect(replaced).toBeNull()
    expect(Buffer.from(token, 'base64url').length).toBeGreaterThanOrEqual(32)
    expect(grant).toEqual({ id: expect.stringMatching(/^[0-9a-f-]{36}$/), ...input(), startedAt: '2026-11-10T10:00:00.000Z', expiresAt: '2026-11-10T10:10:00.000Z' })

    const keys = [...h.redis.keys()].sort()
    expect(keys).toEqual([`jinbe:impersonation:grant:${hashToken(token)}`, 'jinbe:impersonation:session:sess-1'])
    expect([...h.redis.values()].map((e) => e.ttl)).toEqual([600, 600])
    // Nothing in Redis is, or contains, the token itself.
    expect(JSON.stringify([...h.redis])).not.toContain(token)
    expect(h.redis.get('jinbe:impersonation:session:sess-1')!.v).toBe(hashToken(token))
  })

  it('finds a live grant by the token and by the administrator session', async () => {
    const { grant, token } = await impersonationStore.start(input(), 600, NOW)
    expect(await impersonationStore.byToken(token, NOW + 1)).toEqual(grant)
    expect(await impersonationStore.bySession('sess-1', NOW + 1)).toEqual(grant)
    expect(await impersonationStore.byToken('not-the-token', NOW)).toBeNull()
    expect(await impersonationStore.byToken('', NOW)).toBeNull()
    expect(await impersonationStore.bySession('sess-other', NOW)).toBeNull()
  })

  it('no longer answers past its expiry, even if the key outlived its TTL', async () => {
    const { token } = await impersonationStore.start(input(), 600, NOW)
    expect(await impersonationStore.byToken(token, NOW + 599_999)).not.toBeNull()
    expect(await impersonationStore.byToken(token, NOW + 600_000)).toBeNull()
    expect(await impersonationStore.bySession('sess-1', NOW + 600_000)).toBeNull()
  })

  it('keeps one grant per administrator session: a new one replaces the previous', async () => {
    const first = await impersonationStore.start(input(), 600, NOW)
    const second = await impersonationStore.start(input({ targetId: 'user-2', targetEmail: 'cy@example.com', targetName: 'Cy' }), 300, NOW + 1000)
    expect(second.replaced).toEqual(first.grant)
    expect(await impersonationStore.byToken(first.token, NOW + 1000)).toBeNull()
    expect((await impersonationStore.bySession('sess-1', NOW + 1000))?.targetId).toBe('user-2')
    expect(h.redis.size).toBe(2)
    // Another session of the same administrator has its own.
    const other = await impersonationStore.start(input({ adminSessionId: 'sess-2' }), 300, NOW + 1000)
    expect(other.replaced).toBeNull()
    expect((await impersonationStore.bySession('sess-1', NOW + 1000))?.targetId).toBe('user-2')
  })

  it('ends the grant of a session, returning what was live; nothing to end is fine', async () => {
    const { grant, token } = await impersonationStore.start(input(), 600, NOW)
    expect(await impersonationStore.endForSession('sess-1', NOW)).toEqual(grant)
    expect(h.redis.size).toBe(0)
    expect(await impersonationStore.byToken(token, NOW)).toBeNull()
    expect(await impersonationStore.endForSession('sess-1', NOW)).toBeNull()
  })

  it('treats a value it cannot read as no grant', async () => {
    const { token } = await impersonationStore.start(input(), 600, NOW)
    h.redis.set(`jinbe:impersonation:grant:${hashToken(token)}`, { v: '{not json' })
    expect(await impersonationStore.byToken(token, NOW)).toBeNull()
  })
})
