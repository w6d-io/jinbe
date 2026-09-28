import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// The real sources the health strip reads, against a stub Redis and a stub fetch.

const hash = vi.hoisted(() => ({ value: {} as Record<string, string> }))
vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({ hgetall: async () => hash.value }),
  redisClientService: { isHealthy: async () => true },
}))
vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  return { ...real, env: { ...real.env, LOKI_URL: 'http://loki-gateway.loki.svc/', OPA_URL: 'http://opa:8181' } }
})

const sites = vi.hoisted(() => ({ records: [] as Array<{ applied: boolean; site: { address: { host: string } } }>, states: {} as Record<string, string | undefined> }))
vi.mock('../../sites/repository.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../sites/repository.js')>()),
  sitesRepository: { list: async () => sites.records },
}))
vi.mock('../../sites/sites.service.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../sites/sites.service.js')>()),
  protectionLookup: async () => (host: string) => (sites.states[host] ? { state: sites.states[host] } : null),
}))

import { lokiReady, opalLastSuccess, opaHealthy, wafCoverage } from '../../home/sources.js'

const fetchMock = vi.fn()
beforeEach(() => {
  fetchMock.mockReset().mockResolvedValue(new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => vi.unstubAllGlobals())

describe('opalLastSuccess — only what the current manifest refreshes', () => {
  it('drops the manifest fetch and entries a past manifest listed (per-service, deleted services)', async () => {
    const now = Date.now()
    const old = now - 11 * 3_600_000
    hash.value = {
      bindings: String(now),
      'opal/roles': String(now),
      'opal/api_clients': String(now),
      'opal-datasource': String(old),
      'opal/roles/stairfleet1': String(old),
      'opal/route_map/stairfleet1': String(old),
      'opal/roles/deleted-svc': String(old),
      'opal/groups': 'not-a-number',
    }
    expect(await opalLastSuccess()).toEqual({ bindings: now, 'opal/roles': now, 'opal/api_clients': now })
  })
})

describe('lokiReady', () => {
  it('asks the query path the loki-gateway routes, not /ready (a 404 there)', async () => {
    expect(await lokiReady(250)).toBe(true)
    expect(fetchMock.mock.calls[0][0]).toBe('http://loki-gateway.loki.svc/loki/api/v1/status/buildinfo')
    expect(fetchMock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal)
  })

  it('is down on an error answer or no answer', async () => {
    fetchMock.mockResolvedValueOnce(new Response('', { status: 404 }))
    expect(await lokiReady(250)).toBe(false)
    fetchMock.mockRejectedValueOnce(Object.assign(new Error('timeout'), { name: 'TimeoutError' }))
    expect(await lokiReady(250)).toBe(false)
  })
})

describe('opaHealthy', () => {
  it('asks OPA /health', async () => {
    expect(await opaHealthy(250)).toBe(true)
    expect(fetchMock.mock.calls[0][0]).toBe('http://opa:8181/health')
  })

  it('is down on an error answer or no answer', async () => {
    fetchMock.mockResolvedValueOnce(new Response('', { status: 500 }))
    expect(await opaHealthy(250)).toBe(false)
    fetchMock.mockRejectedValueOnce(new Error('ECONNREFUSED'))
    expect(await opaHealthy(250)).toBe(false)
  })
})

describe('wafCoverage', () => {
  it('counts live sites, and the distinct hosts of those not behind the WAF', async () => {
    const site = (host: string, applied = true) => ({ applied, site: { address: { host } } })
    sites.records = [
      site('echo.authdev.example.com'),
      site('echo-mfa.dev.example.com'),
      site('fleet.dev.example.com'),
      site('superadmin.dev.example.com'), // two sites on one host
      site('SuperAdmin.dev.example.com'),
      site('draft.dev.example.com', false),
      site('lost.example.com'),
    ]
    sites.states = {
      'echo.authdev.example.com': 'waf',
      'echo-mfa.dev.example.com': 'none',
      'fleet.dev.example.com': 'none',
      'superadmin.dev.example.com': 'none',
      'SuperAdmin.dev.example.com': 'none',
      'draft.dev.example.com': 'none',
    }
    expect(await wafCoverage()).toEqual({ total: 6, waf: 1, unknown: 1, unprotectedHosts: 3 })
  })
})
