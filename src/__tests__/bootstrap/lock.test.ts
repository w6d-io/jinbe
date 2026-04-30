import { describe, it, expect, beforeEach, vi } from 'vitest'

const { mockSet, mockEval } = vi.hoisted(() => ({
  mockSet: vi.fn(),
  mockEval: vi.fn(),
}))

vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({ set: mockSet, eval: mockEval }),
  redisClientService: { isHealthy: vi.fn(), disconnect: vi.fn() },
}))

import {
  acquireLock,
  releaseLock,
  generateHolderId,
  LOCK_KEY,
  LOCK_TTL_SECONDS,
} from '../../bootstrap/lock.js'

describe('bootstrap/lock', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('acquireLock', () => {
    it('returns the holder id when SET NX EX succeeds', async () => {
      mockSet.mockResolvedValueOnce('OK')
      const result = await acquireLock('host-123')
      expect(result).toBe('host-123')
      expect(mockSet).toHaveBeenCalledWith(LOCK_KEY, 'host-123', 'EX', LOCK_TTL_SECONDS, 'NX')
    })

    it('returns null when the lock is already held', async () => {
      mockSet.mockResolvedValueOnce(null)
      const result = await acquireLock('host-123')
      expect(result).toBeNull()
    })
  })

  describe('releaseLock', () => {
    it('returns true when the Lua CAS deletes the key', async () => {
      mockEval.mockResolvedValueOnce(1)
      await expect(releaseLock('host-123')).resolves.toBe(true)
    })

    it('returns false when the lock is held by a different runner (CAS no-op)', async () => {
      mockEval.mockResolvedValueOnce(0)
      await expect(releaseLock('host-123')).resolves.toBe(false)
    })

    it('passes the holder id as ARGV[1] for the CAS', async () => {
      mockEval.mockResolvedValueOnce(1)
      await releaseLock('host-123')
      const args = mockEval.mock.calls[0]
      expect(args[2]).toBe(LOCK_KEY)
      expect(args[3]).toBe('host-123')
    })
  })

  describe('generateHolderId', () => {
    it('embeds hostname and pid', () => {
      const id = generateHolderId()
      expect(id).toContain(`-${process.pid}-`)
    })

    it('returns a different id on each call (timestamp salt)', async () => {
      const a = generateHolderId()
      await new Promise((r) => setTimeout(r, 2))
      const b = generateHolderId()
      expect(a).not.toBe(b)
    })
  })
})
