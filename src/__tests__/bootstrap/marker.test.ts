import { describe, it, expect, beforeEach, vi } from 'vitest'

const { mockGet, mockSet, mockDel } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockSet: vi.fn(),
  mockDel: vi.fn(),
}))

vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({ get: mockGet, set: mockSet, del: mockDel }),
  redisClientService: { isHealthy: vi.fn(), disconnect: vi.fn() },
}))

import {
  readMarker,
  writeMarker,
  clearMarker,
  MARKER_KEY,
  MarkerCorruptError,
  type BootstrapMarker,
} from '../../bootstrap/marker.js'

const VALID_MARKER: BootstrapMarker = {
  version: 'v0.3.0',
  schemaVersion: 1,
  gitSha: 'abc1234',
  bootstrappedAt: '2026-04-30T00:00:00Z',
  lastUpgradeAt: '2026-04-30T00:00:00Z',
  previousSchemaVersion: null,
  migrations: [{ from: null, to: 1, appliedAt: '2026-04-30T00:00:00Z', gitSha: 'abc1234' }],
  builtInsHash: { rules: 'sha256:aaa', routeMap: 'sha256:bbb' },
}

describe('bootstrap/marker', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('readMarker', () => {
    it('returns null when marker is absent', async () => {
      mockGet.mockResolvedValueOnce(null)
      await expect(readMarker()).resolves.toBeNull()
      expect(mockGet).toHaveBeenCalledWith(MARKER_KEY)
    })

    it('parses a valid marker payload', async () => {
      mockGet.mockResolvedValueOnce(JSON.stringify(VALID_MARKER))
      const m = await readMarker()
      expect(m?.schemaVersion).toBe(1)
      expect(m?.gitSha).toBe('abc1234')
    })

    it('throws MarkerCorruptError on invalid JSON', async () => {
      mockGet.mockResolvedValueOnce('not-json')
      await expect(readMarker()).rejects.toBeInstanceOf(MarkerCorruptError)
    })

    it('throws MarkerCorruptError when required fields are missing', async () => {
      mockGet.mockResolvedValueOnce(JSON.stringify({ version: 'x' }))
      await expect(readMarker()).rejects.toBeInstanceOf(MarkerCorruptError)
    })
  })

  describe('writeMarker', () => {
    it('serialises the marker as JSON to the canonical key', async () => {
      mockSet.mockResolvedValueOnce('OK')
      await writeMarker(VALID_MARKER)
      expect(mockSet).toHaveBeenCalledWith(MARKER_KEY, JSON.stringify(VALID_MARKER))
    })
  })

  describe('clearMarker', () => {
    it('deletes the canonical key', async () => {
      mockDel.mockResolvedValueOnce(1)
      await clearMarker()
      expect(mockDel).toHaveBeenCalledWith(MARKER_KEY)
    })
  })
})
