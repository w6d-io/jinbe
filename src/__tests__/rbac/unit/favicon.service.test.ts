import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// In-memory Redis mock that understands `set(key, value, 'EX', ttl)` so we can
// assert on the TTL the favicon service writes.
const { redisMock, redisModule } = vi.hoisted(() => {
  class InlineRedisMock {
    store = new Map<string, string>()
    ttls = new Map<string, number>()
    async get(key: string) { return this.store.get(key) ?? null }
    async set(key: string, value: string, mode?: string, ttl?: number) {
      this.store.set(key, value)
      if (mode === 'EX' && typeof ttl === 'number') this.ttls.set(key, ttl)
      return 'OK' as const
    }
    async del(...keys: string[]) { let c = 0; for (const k of keys) { if (this.store.delete(k)) c++; this.ttls.delete(k) } return c }
    clear() { this.store.clear(); this.ttls.clear() }
  }
  const mock = new InlineRedisMock()
  return {
    redisMock: mock,
    redisModule: {
      redisClientService: { getClient: () => mock, isHealthy: vi.fn().mockResolvedValue(true), disconnect: vi.fn().mockResolvedValue(undefined), isConnected: true },
      getRedisClient: () => mock,
    },
  }
})

vi.mock('../../../services/redis-client.service.js', () => redisModule)

import { faviconService } from '../../../services/favicon.service.js'

const PNG = Buffer.from('89504e470d0a1a0a', 'hex') // tiny PNG signature stand-in

// Build a minimal Response for the fetch mock.
function res(body: Buffer | string, contentType: string, status = 200, extraHeaders: Record<string, string> = {}) {
  const buf = typeof body === 'string' ? Buffer.from(body, 'utf8') : body
  const headers: Record<string, string> = { 'content-type': contentType, ...extraHeaders }
  return new Response(buf, { status, headers })
}

// Seed one Oathkeeper access rule for a service so origin derivation resolves.
async function seedRule(service: string, matchUrl: string) {
  await redisMock.set('rbac:oathkeeper:rules', JSON.stringify([
    { id: service, upstream: { url: 'http://x' }, match: { url: matchUrl, methods: ['GET'] }, authenticators: [], authorizer: { handler: 'allow' }, mutators: [] },
  ]))
}

describe('FaviconService', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    redisMock.clear()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('resolveOrigin', () => {
    it('derives host from a plain match.url', async () => {
      await seedRule('shop', 'https://shop.example.com/api/shop/<**>')
      expect(await faviconService.resolveOrigin('shop')).toBe('https://shop.example.com')
    })

    it('derives host from a regex-wrapped match.url with https? scheme', async () => {
      await seedRule('shop', '<https?://shop.example.io/.*>')
      expect(await faviconService.resolveOrigin('shop')).toBe('https://shop.example.io')
    })

    it('preserves an explicit port', async () => {
      await seedRule('shop', 'https://shop.example.com:8443/api/shop/<**>')
      expect(await faviconService.resolveOrigin('shop')).toBe('https://shop.example.com:8443')
    })

    it('returns null for a wildcard/templated host', async () => {
      await seedRule('shop', 'https://<.*>.example.com/<**>')
      expect(await faviconService.resolveOrigin('shop')).toBeNull()
    })

    it('returns null when no rule matches the service', async () => {
      await seedRule('other', 'https://other.example.com/<**>')
      expect(await faviconService.resolveOrigin('shop')).toBeNull()
    })
  })

  describe('getFavicon', () => {
    it('returns a cached positive result without fetching', async () => {
      await redisMock.set('favicon:shop', JSON.stringify({ ct: 'image/png', b64: PNG.toString('base64') }))
      const fetchMock = vi.fn()
      vi.stubGlobal('fetch', fetchMock)

      const r = await faviconService.getFavicon('shop')
      expect(r).not.toBeNull()
      expect(r!.contentType).toBe('image/png')
      expect(r!.data.equals(PNG)).toBe(true)
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it('returns null on a negative cache hit without fetching', async () => {
      await redisMock.set('favicon:shop', 'none')
      const fetchMock = vi.fn()
      vi.stubGlobal('fetch', fetchMock)

      expect(await faviconService.getFavicon('shop')).toBeNull()
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it('parses a declared <link rel="icon">, fetches it, and caches 7d', async () => {
      await seedRule('shop', 'https://shop.example.com/api/shop/<**>')
      const fetchMock = vi.fn(async (url: string) => {
        if (url === 'https://shop.example.com/') {
          return res('<html><head><link rel="icon" href="/brand/icon.png"></head></html>', 'text/html')
        }
        if (url === 'https://shop.example.com/brand/icon.png') {
          return res(PNG, 'image/png', 200, { 'content-length': String(PNG.byteLength) })
        }
        return res('', 'text/plain', 404)
      })
      vi.stubGlobal('fetch', fetchMock)

      const r = await faviconService.getFavicon('shop')
      expect(r).not.toBeNull()
      expect(r!.contentType).toBe('image/png')
      expect(r!.data.equals(PNG)).toBe(true)
      // Cached positive with a 7-day TTL.
      expect(redisMock.ttls.get('favicon:shop')).toBe(7 * 24 * 60 * 60)
      const env = JSON.parse(redisMock.store.get('favicon:shop')!)
      expect(env.ct).toBe('image/png')
    })

    it('falls back to /favicon.ico when no <link> is declared', async () => {
      await seedRule('shop', 'https://shop.example.com/api/shop/<**>')
      const fetchMock = vi.fn(async (url: string) => {
        if (url === 'https://shop.example.com/') return res('<html><head></head></html>', 'text/html')
        if (url === 'https://shop.example.com/favicon.ico') return res(PNG, 'image/x-icon')
        return res('', 'text/plain', 404)
      })
      vi.stubGlobal('fetch', fetchMock)

      const r = await faviconService.getFavicon('shop')
      expect(r).not.toBeNull()
      expect(r!.contentType).toBe('image/x-icon')
    })

    it('ignores an off-host declared icon (SSRF guard) and uses /favicon.ico', async () => {
      await seedRule('shop', 'https://shop.example.com/api/shop/<**>')
      const fetchMock = vi.fn(async (url: string) => {
        if (url === 'https://shop.example.com/') {
          return res('<html><head><link rel="icon" href="https://evil.example.net/x.png"></head></html>', 'text/html')
        }
        if (url === 'https://shop.example.com/favicon.ico') return res(PNG, 'image/png')
        return res('', 'text/plain', 404)
      })
      vi.stubGlobal('fetch', fetchMock)

      await faviconService.getFavicon('shop')
      // The off-host icon must never be fetched.
      expect(fetchMock).not.toHaveBeenCalledWith('https://evil.example.net/x.png', expect.anything())
    })

    it('rejects a non-image content-type', async () => {
      await seedRule('shop', 'https://shop.example.com/api/shop/<**>')
      const fetchMock = vi.fn(async (url: string) => {
        if (url === 'https://shop.example.com/') return res('<html><head></head></html>', 'text/html')
        if (url === 'https://shop.example.com/favicon.ico') return res('<!doctype html>', 'text/html')
        return res('', 'text/plain', 404)
      })
      vi.stubGlobal('fetch', fetchMock)

      const r = await faviconService.getFavicon('shop')
      expect(r).toBeNull()
      // Negative cached with the shorter 1-day TTL.
      expect(redisMock.store.get('favicon:shop')).toBe('none')
      expect(redisMock.ttls.get('favicon:shop')).toBe(24 * 60 * 60)
    })

    it('rejects an over-size image (100KB cap) even without content-length', async () => {
      await seedRule('shop', 'https://shop.example.com/api/shop/<**>')
      const big = Buffer.alloc(200 * 1024, 1)
      const fetchMock = vi.fn(async (url: string) => {
        if (url === 'https://shop.example.com/') return res('<html><head></head></html>', 'text/html')
        if (url === 'https://shop.example.com/favicon.ico') return res(big, 'image/png') // no content-length
        return res('', 'text/plain', 404)
      })
      vi.stubGlobal('fetch', fetchMock)

      expect(await faviconService.getFavicon('shop')).toBeNull()
      expect(redisMock.store.get('favicon:shop')).toBe('none')
    })

    it('caches a negative sentinel (1d) when there is no usable host', async () => {
      await seedRule('shop', 'https://<.*>.example.com/<**>') // unparseable host
      const fetchMock = vi.fn()
      vi.stubGlobal('fetch', fetchMock)

      expect(await faviconService.getFavicon('shop')).toBeNull()
      expect(fetchMock).not.toHaveBeenCalled()
      expect(redisMock.store.get('favicon:shop')).toBe('none')
      expect(redisMock.ttls.get('favicon:shop')).toBe(24 * 60 * 60)
    })

    it('never throws when fetch rejects', async () => {
      await seedRule('shop', 'https://shop.example.com/api/shop/<**>')
      vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network down') }))

      expect(await faviconService.getFavicon('shop')).toBeNull()
      expect(redisMock.store.get('favicon:shop')).toBe('none')
    })
  })
})
