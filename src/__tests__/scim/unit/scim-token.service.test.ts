import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createHash } from 'node:crypto'

// In-memory Redis hash stand-in — the token service only uses hset/hget/hgetall/hdel.
const store = new Map<string, string>()
const redisMock = {
  hset: vi.fn(async (_key: string, field: string, value: string) => {
    store.set(field, value)
    return 1
  }),
  hget: vi.fn(async (_key: string, field: string) => store.get(field) ?? null),
  hgetall: vi.fn(async () => Object.fromEntries(store)),
  hdel: vi.fn(async (_key: string, field: string) => (store.delete(field) ? 1 : 0)),
}

vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => redisMock,
}))

import { ScimTokenService } from '../../../services/scim-token.service.js'

describe('ScimTokenService', () => {
  let service: ScimTokenService

  beforeEach(() => {
    vi.clearAllMocks()
    store.clear()
    service = new ScimTokenService()
  })

  it('mint stores only the SHA-256 hash, never the plaintext', async () => {
    const { tokenId, token } = await service.mint({ label: 'entra', createdBy: 'admin@x.dev' })

    expect(token).toMatch(/^scim_[0-9a-f]{16}_[0-9a-f]{64}$/)
    expect(token).toContain(tokenId)
    const stored = JSON.parse(store.get(tokenId)!)
    expect(stored.sha256).toBe(createHash('sha256').update(token).digest('hex'))
    expect(JSON.stringify(stored)).not.toContain(token)
    expect(stored.label).toBe('entra')
    expect(stored.createdBy).toBe('admin@x.dev')
    expect(stored.lastUsedAt).toBeNull()
  })

  it('verify accepts a minted token and returns its principal', async () => {
    const { tokenId, token } = await service.mint({ label: 'google' })
    const principal = await service.verify(token)
    expect(principal).toEqual({ tokenId, label: 'google' })
  })

  it('verify rejects a wrong secret with a valid tokenId prefix', async () => {
    const { tokenId } = await service.mint({ label: 'entra' })
    const forged = `scim_${tokenId}_${'0'.repeat(64)}`
    expect(await service.verify(forged)).toBeNull()
  })

  it('verify rejects unknown ids, garbage, and empty tokens', async () => {
    await service.mint({ label: 'entra' })
    expect(await service.verify(`scim_${'a'.repeat(16)}_${'b'.repeat(64)}`)).toBeNull()
    expect(await service.verify('not-a-token')).toBeNull()
    expect(await service.verify('')).toBeNull()
  })

  it('verify rejects a revoked token', async () => {
    const { tokenId, token } = await service.mint({ label: 'entra' })
    expect(await service.revoke(tokenId)).toBe(true)
    expect(await service.verify(token)).toBeNull()
    expect(await service.revoke(tokenId)).toBe(false)
  })

  it('verify bumps lastUsedAt (best-effort)', async () => {
    const { tokenId, token } = await service.mint({ label: 'entra' })
    await service.verify(token)
    // touch() is fire-and-forget; drain the microtask queue.
    await new Promise((resolve) => setImmediate(resolve))
    const stored = JSON.parse(store.get(tokenId)!)
    expect(stored.lastUsedAt).not.toBeNull()
  })

  it('list returns metadata without the hash', async () => {
    await service.mint({ label: 'entra' })
    await service.mint({ label: 'google' })
    const tokens = await service.list()
    expect(tokens).toHaveLength(2)
    expect(tokens.map((t) => t.label).sort()).toEqual(['entra', 'google'])
    for (const t of tokens) {
      expect(t).not.toHaveProperty('sha256')
    }
  })

  it('tolerates corrupt records in the hash', async () => {
    store.set('deadbeefdeadbeef', 'not json')
    const { token } = await service.mint({ label: 'entra' })
    expect(await service.verify(token)).not.toBeNull()
    expect(await service.list()).toHaveLength(1)
  })
})
