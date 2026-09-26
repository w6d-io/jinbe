import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { FakeLoki } from './mocks.js'

// OBS-4.1: /api/admin/observability/{logs,trace,links}. Ops logs are pinned to this environment's
// namespace and never include the audit stream; windows and line counts are capped; ids are
// validated; nothing personal goes into a Grafana URL.

const cfg = vi.hoisted(() => ({
  LOKI_NAMESPACE: 'auth' as string | undefined,
  TEMPO_URL: 'http://tempo.tempo:3200' as string | undefined,
  GRAFANA_URL: 'https://grafana.example.com' as string | undefined,
  GRAFANA_LOKI_DATASOURCE_UID: 'loki-uid',
  GRAFANA_TEMPO_DATASOURCE_UID: 'tempo-uid' as string | undefined,
}))
vi.mock('../../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../config/env.js')>()
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in cfg ? cfg[k as keyof typeof cfg] : t[k as keyof typeof t]) }) }
})
vi.mock('../../../middleware/require-admin.js', async () => {
  const { enforcing } = await import('../../../policy/declared-routes.js')
  return {
    requireAdmin: enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
      if (request.headers['x-test-admin'] !== 'yes') return reply.status(403).send({ error: 'Forbidden' })
    }, 'admin:read'),
  }
})

import { setLokiClient } from '../../../audit/query/loki.js'
import { observabilityRoutes } from '../../../routes/observability.routes.js'
import { declaredRoutes } from '../../../policy/declared-routes.js'

const loki = new FakeLoki()
const HOUR = 3_600_000
const NOW = Date.now()
const iso = (ms: number) => new Date(ms).toISOString()
const TRACE = '4bf92f3577b34da6a3ce929d0e0e4736'

let app: FastifyInstance
beforeAll(async () => {
  setLokiClient(loki)
  app = Fastify()
  await app.register(observabilityRoutes, { prefix: '/api/admin/observability' })
  await app.ready()
})
afterAll(async () => { await app.close(); setLokiClient(null) })
beforeEach(() => {
  loki.down = false
  loki.queries = []
  loki.ranges = []
  loki.entries = [
    { ts: `${BigInt(NOW - 1000) * 1_000_000n}`, line: JSON.stringify({ level: 30, msg: 'user alice@example.com logged in', token: 'ory_st_abcdefghijklmnop', request_id: 'req-1' }), labels: { container: 'jinbe' } },
  ]
})

const get = (url: string, admin = true) => app.inject({ method: 'GET', url, headers: admin ? { 'x-test-admin': 'yes' } : {} })

describe('GET /logs', () => {
  it('is admin only', async () => {
    expect((await get('/api/admin/observability/logs', false)).statusCode).toBe(403)
  })

  it('pins the namespace, excludes audit, defaults to 1 h and re-redacts the lines', async () => {
    const res = await get('/api/admin/observability/logs?request_id=req-1&service=jinbe')
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(loki.queries[0].startsWith('{namespace="auth", log_type!="audit"')).toBe(true)
    expect(BigInt(loki.ranges[0].endNs) - BigInt(loki.ranges[0].startNs)).toBe(BigInt(HOUR) * 1_000_000n)
    expect(JSON.stringify(body)).not.toContain('alice@example.com')
    expect(JSON.stringify(body)).not.toContain('ory_st_abcdefghijklmnop')
    expect(body).toMatchObject({ namespace: 'auth', truncated: false, source: 'loki' })
    expect(body.lines).toHaveLength(1)
  })

  it('caps the window at 24 h and the lines at 1000', async () => {
    expect((await get(`/api/admin/observability/logs?since=${iso(NOW - 25 * HOUR)}&until=${iso(NOW)}`)).statusCode).toBe(400)
    expect((await get('/api/admin/observability/logs?limit=1001')).statusCode).toBe(400)
  })

  it('accepts only allow-listed services and well-formed ids', async () => {
    expect((await get('/api/admin/observability/logs?service=grafana')).statusCode).toBe(400)
    expect((await get('/api/admin/observability/logs?trace_id=zz')).statusCode).toBe(400)
    expect((await get(`/api/admin/observability/logs?request_id=${encodeURIComponent('a" |= "')}`)).statusCode).toBe(400)
    expect((await get('/api/admin/observability/logs?log_type=audit')).statusCode).toBe(400)
  })

  it('Loki down → 503', async () => {
    loki.down = true
    expect((await get('/api/admin/observability/logs')).statusCode).toBe(503)
  })
})

describe('GET /trace/:traceId', () => {
  it('validates the id and summarises spans without attributes', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      batches: [{
        resource: { attributes: [{ key: 'service.name', value: { stringValue: 'jinbe' } }] },
        scopeSpans: [{ spans: [{ name: 'GET /api/x', spanId: 'a1', startTimeUnixNano: '1000000000', endTimeUnixNano: '1250000000', status: { code: 2 }, attributes: [{ key: 'http.request.header.cookie', value: { stringValue: 'secret' } }] }] }],
      }],
    }), { status: 200 }))
    expect((await get('/api/admin/observability/trace/not-hex')).statusCode).toBe(400)
    const res = await get(`/api/admin/observability/trace/${TRACE}`)
    expect(res.statusCode).toBe(200)
    expect(fetchMock.mock.calls[0][0]).toBe(`http://tempo.tempo:3200/api/traces/${TRACE}`)
    expect(res.json().spans[0]).toEqual({ service: 'jinbe', name: 'GET /api/x', spanId: 'a1', durationMs: 250, status: 'error' })
    expect(res.body).not.toContain('secret')
    fetchMock.mockRestore()
  })

  it('Tempo not configured → 404; unreachable → 503; unknown trace → 404', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('ECONNREFUSED'))
    expect((await get(`/api/admin/observability/trace/${TRACE}`)).statusCode).toBe(503)
    fetchMock.mockResolvedValueOnce(new Response('', { status: 404 }))
    expect((await get(`/api/admin/observability/trace/${TRACE}`)).statusCode).toBe(404)
    fetchMock.mockRestore()
    cfg.TEMPO_URL = undefined
    expect((await get(`/api/admin/observability/trace/${TRACE}`)).statusCode).toBe(404)
    cfg.TEMPO_URL = 'http://tempo.tempo:3200'
  })
})

describe('GET /links', () => {
  it('builds Grafana explore links from ids only', async () => {
    const res = await get(`/api/admin/observability/links?request_id=req-9fa6&trace_id=${TRACE}`)
    expect(res.statusCode).toBe(200)
    const { links } = res.json()
    expect(links.trace).toContain('https://grafana.example.com/explore')
    expect(decodeURIComponent(links.trace)).toContain(TRACE)
    expect(decodeURIComponent(links.logs)).toContain('req-9fa6')
    expect((await get('/api/admin/observability/links?request_id=a@b.com')).statusCode).toBe(400)
  })
})

describe('route table', () => {
  it('declares admin:read on every observability route', () => {
    const rows = declaredRoutes().filter((r) => r.path.startsWith('/api/admin/observability') && r.method === 'GET')
    expect(rows.length).toBe(3)
    for (const r of rows) expect(r.permission).toBe('admin:read')
  })
})
