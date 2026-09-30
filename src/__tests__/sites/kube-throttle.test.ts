import { describe, it, expect, beforeEach, vi } from 'vitest'
import type * as k8s from '@kubernetes/client-node'

// The API server's 429 (API Priority and Fairness, a watch cache re-initialising) is retried with
// backoff, honouring Retry-After, and surfaces as a retryable `kubernetes_rate_limited`; the
// cluster-wide lists every render/preview reads are one shared short-lived copy, not a list per request.

import { CLUSTER_LIST_TTL_MS, ClientNodeKubeSites, KubeThrottled, KubeUnavailable, STALE_ON_ERROR_MS, THROTTLE_BACKOFF_MS, resetClusterLists, retryThrottled, setThrottleSleep } from '../../sites/kube-sites.js'
import { fail } from '../../sites/http.js'

const tooMany = (retryAfter?: string) => Object.assign(new Error('HTTP-Code: 429'), { code: 429, body: { message: 'Too many requests' }, headers: retryAfter ? { 'retry-after': retryAfter } : {} })
const zone = (name: string) => ({ metadata: { name }, spec: { domain: `${name}.example.com` } })

let waits: number[]
beforeEach(() => {
  waits = []
  setThrottleSleep(async (ms) => { waits.push(ms) })
  resetClusterLists()
})

function client(custom: Record<string, unknown>) {
  return new ClientNodeKubeSites(custom as unknown as k8s.CustomObjectsApi, {} as k8s.NetworkingV1Api, 'auth')
}

describe('retryThrottled', () => {
  it('retries a 429 with backoff and returns the answer', async () => {
    const fn = vi.fn().mockRejectedValueOnce(tooMany()).mockRejectedValueOnce(tooMany()).mockResolvedValue('ok')
    await expect(retryThrottled('list zones', fn)).resolves.toBe('ok')
    expect(fn).toHaveBeenCalledTimes(3)
    expect(waits).toEqual(THROTTLE_BACKOFF_MS.slice(0, 2))
  })

  it('waits what Retry-After says when it is short', async () => {
    const fn = vi.fn().mockRejectedValueOnce(tooMany('1')).mockResolvedValue('ok')
    await retryThrottled('list zones', fn)
    expect(waits).toEqual([1000])
  })

  it('gives up after the backoff as KubeThrottled: 503, retryable code, Retry-After', async () => {
    const fn = vi.fn().mockRejectedValue(tooMany())
    const err = await retryThrottled('list zones', fn).catch((e) => e)
    expect(fn).toHaveBeenCalledTimes(THROTTLE_BACKOFF_MS.length + 1)
    expect(err).toBeInstanceOf(KubeThrottled)
    expect(err).toBeInstanceOf(KubeUnavailable)
    expect(err).toMatchObject({ statusCode: 503, code: 'kubernetes_rate_limited', retryAfterSec: 1 })
    expect(err.message).toMatch(/temporarily rate-limiting.*retry in a few seconds \(list zones: 429\)/)
  })

  it('does not hold a request for a long Retry-After: fails at once with it', async () => {
    const fn = vi.fn().mockRejectedValue(tooMany('20'))
    const err = await retryThrottled('list zones', fn).catch((e) => e)
    expect(fn).toHaveBeenCalledTimes(1)
    expect(err).toMatchObject({ code: 'kubernetes_rate_limited', retryAfterSec: 20 })
  })

  it('retries a 5xx with the same backoff, then rethrows it as it came', async () => {
    const flaky = vi.fn().mockRejectedValueOnce(Object.assign(new Error('x'), { code: 503 })).mockResolvedValue('ok')
    await expect(retryThrottled('list zones', flaky)).resolves.toBe('ok')
    const down = vi.fn().mockRejectedValue(Object.assign(new Error('x'), { code: 500 }))
    await expect(retryThrottled('list zones', down)).rejects.toMatchObject({ code: 500 })
    expect(down).toHaveBeenCalledTimes(THROTTLE_BACKOFF_MS.length + 1)
  })

  it('never retries a write that answered 5xx (it may have landed)', async () => {
    const fn = vi.fn().mockRejectedValue(Object.assign(new Error('x'), { code: 500 }))
    await expect(retryThrottled('create site', fn, { write: true })).rejects.toMatchObject({ code: 500 })
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('never retries a 4xx other than 429', async () => {
    const fn = vi.fn().mockRejectedValue(Object.assign(new Error('x'), { code: 403 }))
    await expect(retryThrottled('list zones', fn)).rejects.toMatchObject({ code: 403 })
    expect(fn).toHaveBeenCalledTimes(1)
  })
})

describe('ClientNodeKubeSites cluster lists', () => {
  it('a 429 that persists is kubernetes_rate_limited, not a plain outage', async () => {
    const kube = client({ listClusterCustomObject: vi.fn().mockRejectedValue(tooMany()) })
    await expect(kube.listZones()).rejects.toMatchObject({ code: 'kubernetes_rate_limited' })
  })

  it('other failures stay kubernetes_unavailable', async () => {
    const kube = client({ listClusterCustomObject: vi.fn().mockRejectedValue(Object.assign(new Error('x'), { code: 500 })) })
    await expect(kube.listZones()).rejects.toMatchObject({ code: 'kubernetes_unavailable', message: expect.stringContaining('list zones: 500') })
  })

  it('concurrent and repeated reads share one list call', async () => {
    const list = vi.fn(async () => ({ items: [zone('a')] }))
    const kube = client({ listClusterCustomObject: list })
    const all = await Promise.all(Array.from({ length: 10 }, () => kube.listZones()))
    expect(all.every((z) => z.length === 1)).toBe(true)
    await kube.listZones()
    expect(list).toHaveBeenCalledTimes(1)
  })

  it('a Zone write through jinbe drops the copy: the next read lists again', async () => {
    let items = [zone('a')]
    const list = vi.fn(async () => ({ items }))
    const kube = client({ listClusterCustomObject: list, createClusterCustomObject: vi.fn(async () => ({})) })
    expect(await kube.listZones()).toHaveLength(1)
    items = [zone('a'), zone('b')]
    await kube.createZone(zone('b') as never)
    await vi.waitFor(async () => expect(await kube.listZones()).toHaveLength(2))
    expect(list).toHaveBeenCalledTimes(2)
  })

  it('the copy is kept 30 s, then listed again', async () => {
    vi.useFakeTimers({ now: new Date('2026-09-30T10:00:00Z'), toFake: ['Date'] })
    try {
      const list = vi.fn(async () => ({ items: [zone('a')] }))
      const kube = client({ listClusterCustomObject: list })
      await kube.listZones()
      vi.setSystemTime(Date.now() + CLUSTER_LIST_TTL_MS - 1_000)
      await kube.listZones()
      expect(list).toHaveBeenCalledTimes(1)
      vi.setSystemTime(Date.now() + 2_000)
      await kube.listZones()
      expect(list).toHaveBeenCalledTimes(2)
    } finally {
      vi.useRealTimers()
    }
  })

  it('stale while error: the API down after the retries serves the last list, up to STALE_ON_ERROR_MS', async () => {
    vi.useFakeTimers({ now: new Date('2026-09-30T10:00:00Z'), toFake: ['Date'] })
    try {
      let up = true
      const list = vi.fn(async () => {
        if (!up) throw Object.assign(new Error('x'), { code: 503 })
        return { items: [zone('a')] }
      })
      const kube = client({ listClusterCustomObject: list })
      expect(await kube.listZones()).toHaveLength(1)
      up = false
      vi.setSystemTime(Date.now() + CLUSTER_LIST_TTL_MS + 1_000)
      expect(await kube.listZones()).toHaveLength(1)
      vi.setSystemTime(Date.now() + STALE_ON_ERROR_MS)
      await expect(kube.listZones()).rejects.toMatchObject({ code: 'kubernetes_unavailable' })
    } finally {
      vi.useRealTimers()
    }
  })

  it('HTTPRoutes and ListenerSets are shared the same way, per kind', async () => {
    const list = vi.fn(async ({ plural }: { plural: string }) => ({ items: [{ metadata: { name: plural, namespace: 'n' }, spec: {} }] }))
    const kube = client({ listClusterCustomObject: list })
    await Promise.all([kube.listHTTPRoutes(), kube.listHTTPRoutes(), kube.listListenerSets(), kube.listListenerSets()])
    expect(list.mock.calls.map(([a]) => a.plural).sort()).toEqual(['httproutes', 'listenersets'])
  })
})

describe('the Sites error shape', () => {
  it('a throttled answer carries Retry-After', () => {
    const reply = { status: vi.fn().mockReturnThis(), header: vi.fn().mockReturnThis(), send: vi.fn().mockReturnThis() }
    const request = { log: { error: vi.fn() } }
    fail(reply as never, request as never, new KubeThrottled('list zones: 429', 2))
    expect(reply.status).toHaveBeenCalledWith(503)
    expect(reply.header).toHaveBeenCalledWith('retry-after', '2')
    expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({ error: 'kubernetes_rate_limited' }))
  })
})
