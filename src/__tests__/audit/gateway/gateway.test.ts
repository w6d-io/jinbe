import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// Gateway decisions (allowed AND refused) read as counts from the gateway's own log: per subject
// and host over a window for the console, per subject and host per hour into the audit trail.

const h = vi.hoisted(() => ({
  platform: new Set<string>(['root']),
  admins: { 'org-admin-a': ['org-a'] } as Record<string, string[]>,
  redis: null as unknown,
  emitted: [] as unknown[],
}))
vi.mock('../../../authz/opa.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../authz/opa.js')>()),
  rights: vi.fn(async (email: string) => ({ groups: [], roles: [], permissions: h.platform.has(email.split('@')[0]) ? ['admin:read'] : [] })),
  manageableOrgs: vi.fn(async (email: string) => h.admins[email.split('@')[0]] ?? []),
}))
vi.mock('../../../services/redis-client.service.js', async () => {
  const { MemoryRedis } = await import('../query/mocks.js')
  h.redis = new MemoryRedis()
  return { getRedisClient: () => h.redis }
})
vi.mock('../../../audit/v1/index.js', () => ({ auditLog: { emit: vi.fn(async (e: unknown) => { h.emitted.push(e); return e }) } }))

import { setLokiClient, LokiUnavailableError, type LokiClient, type LokiSample } from '../../../audit/query/loki.js'
import { fold, gatewayAccess, gatewayQuery, subjectKind } from '../../../audit/gateway/decisions.js'
import { hourEvents, rollupTick } from '../../../audit/gateway/rollup.js'
import { gatewayAccessRoute } from '../../../audit/gateway/routes.js'
import { buildEvent } from '../../../audit/v1/emitter.js'
import { auditEventV1Schema } from '../../../audit/v1/schema.js'

const ANA = '0f912cf8-03a1-492d-96d5-148389fc794c'
const BOB = 'c1a5623e-5c44-48f1-b9f6-1baf2b9f6baa'
const sample = (granted: boolean, subject: string, host: string, value: number): LokiSample => ({ metric: { granted: String(granted), subject, host }, value })

class GatewayLoki implements LokiClient {
  samples: LokiSample[] = []
  queries: string[] = []
  down = false
  tooWide = false
  async queryRange() { return [] }
  async instant(query: string): Promise<LokiSample[]> {
    this.queries.push(query)
    if (this.down) throw new LokiUnavailableError('connect ECONNREFUSED')
    if (this.tooWide && !query.startsWith('topk') && query.includes('granted, subject, host')) throw new LokiUnavailableError('loki answered 400', 400)
    // The partial edges of a window (under an hour) are empty here: everything sits in the middle.
    if (!query.startsWith('topk') && Number(/\[(\d+)s\]/.exec(query)![1]) < 3600) return []
    return query.includes('sum by (granted)') ? regroup(this.samples) : this.samples
  }
  async range(query: string, start: number, end: number) {
    this.queries.push(query)
    if (this.down) throw new LokiUnavailableError('connect ECONNREFUSED')
    if (this.tooWide && query.includes('granted, subject, host')) throw new LokiUnavailableError('loki answered 400', 400)
    const samples = query.includes('sum by (granted)') ? regroup(this.samples) : this.samples
    // Everything in the one middle point.
    return samples.map((s) => ({ metric: s.metric, values: [[Math.floor((start + end) / 2 / 3600) * 3600 || start, s.value]] as Array<[number, number]> }))
  }
}
function regroup(samples: LokiSample[]): LokiSample[] {
  const by = new Map<string, number>()
  for (const s of samples) by.set(s.metric.granted, (by.get(s.metric.granted) ?? 0) + s.value)
  return [...by.entries()].map(([granted, value]) => ({ metric: { granted }, value }))
}

const loki = new GatewayLoki()
beforeEach(() => { loki.samples = []; loki.queries = []; loki.down = false; loki.tooWide = false; h.emitted = []; setLokiClient(loki) })
afterAll(() => setLokiClient(null))

describe('the gateway query', () => {
  it('reads the gateway container in the namespace, groups on subject and host only, filters as literals', () => {
    const q = gatewayQuery({ subject: ANA, host: 'echo.example.com' }, 'auth-dev', 'oathkeeper')
    expect(q).toBe(`{namespace="auth-dev", container="oathkeeper"} |= "Access request" | json granted="granted", subject="subject", host="http_host" | subject="${ANA}" | host="echo.example.com"`)
  })

  it('a UUID is a person, anything else named is a client, nothing (or guest) is nobody', () => {
    expect(subjectKind(ANA)).toBe('user')
    expect(subjectKind('ci-deployer')).toBe('service')
    expect(subjectKind('')).toBe('anonymous')
    expect(subjectKind('guest')).toBe('anonymous')
  })
})

describe('fold', () => {
  it('per subject and per host, unauthenticated counted apart', () => {
    const r = fold([
      sample(true, ANA, 'echo', 40), sample(false, ANA, 'echo', 2), sample(true, ANA, 'kuma', 5),
      sample(true, 'ci-deployer', 'api', 7),
      sample(false, '', 'kuma', 500), sample(true, 'guest', 'auth', 3),
    ])
    expect(r.totals).toEqual({ allowed: 55, denied: 502, unauthenticated: { allowed: 3, denied: 500 } })
    expect(r.subjects[0]).toEqual({ subject: ANA, kind: 'user', allowed: 45, denied: 2, hosts: ['echo', 'kuma'] })
    expect(r.subjects[1]).toMatchObject({ subject: 'ci-deployer', kind: 'service' })
    expect(r.subjects.some((s) => s.subject === '' || s.subject === 'guest')).toBe(false)
    expect(r.hosts[0]).toEqual({ host: 'kuma', allowed: 5, denied: 500, unauthenticated: 500 })
  })
})

describe('gatewayAccess', () => {
  const to = Date.UTC(2026, 8, 28, 12, 20)
  const from = to - 24 * 3_600_000

  it('allowed and denied, by subject and host, with a histogram whose sum is the total', async () => {
    loki.samples = [sample(true, ANA, 'echo', 10), sample(false, '', 'kuma', 90)]
    const r = await gatewayAccess({}, from, to)
    expect(r.totals.allowed).toBe(10)
    expect(r.totals.denied).toBe(90)
    expect(r.series.reduce((a, b) => a + b.allowed + b.denied, 0)).toBe(100)
    expect(r.truncated).toBe(false)
  })

  it('too many subjects for Loki: the breakdown is a top 200, the totals still whole, marked truncated', async () => {
    loki.tooWide = true
    loki.samples = [sample(true, ANA, 'echo', 10)]
    const r = await gatewayAccess({}, from, to)
    expect(loki.queries.some((q) => q.startsWith('topk(200, sum by (granted, subject, host)'))).toBe(true)
    expect(r.truncated).toBe(true)
    expect(r.totals.allowed).toBe(10)
  })
})

describe('GET /api/audit/access', () => {
  let app: FastifyInstance
  const now = Date.now()
  const iso = (ms: number) => new Date(ms).toISOString()
  const day = `from=${iso(now - 86_400_000)}&to=${iso(now)}`
  beforeAll(async () => {
    app = Fastify()
    app.addHook('onRequest', async (request) => {
      const id = request.headers['x-test-subject'] as string | undefined
      if (id) request.userContext = { id, email: `${id}@example.com`, name: id }
    })
    await app.register(gatewayAccessRoute, { prefix: '/api/audit' })
    await app.ready()
  })
  afterAll(async () => { await app.close() })
  const get = (url: string, who = 'root') => app.inject({ method: 'GET', url, headers: { 'x-test-subject': who } })

  it('platform reader: 200 with totals, subjects, hosts, series', async () => {
    loki.samples = [sample(true, ANA, 'echo', 3)]
    const res = await get(`/api/audit/access?${day}`)
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ totals: { allowed: 3 }, source: 'gateway-log', scope: { platform: true } })
  })

  it('an org admin: 403 — the gateway names no organisation to cut the view to', async () => {
    const res = await get(`/api/audit/access?${day}`, 'org-admin-a')
    expect(res.statusCode).toBe(403)
    expect(res.json().error).toBe('platform_only')
  })

  it('refuses unknown parameters and malformed filters; Loki down is a 503', async () => {
    expect((await get(`/api/audit/access?${day}&query={x}`)).statusCode).toBe(400)
    expect((await get(`/api/audit/access?${day}&host=a"b`)).statusCode).toBe(400)
    loki.down = true
    expect((await get(`/api/audit/access?${day}`)).statusCode).toBe(503)
  })
})

describe('the hourly rollup (access.summary)', () => {
  const endS = Date.UTC(2026, 8, 28, 12) / 1000

  it('one valid audit/v1 event per subject and host; unauthenticated as an anonymous actor', async () => {
    loki.samples = [sample(true, ANA, 'echo', 40), sample(false, ANA, 'echo', 2), sample(false, '', 'kuma', 900), sample(true, 'ci-deployer', 'api', 1)]
    const events = await hourEvents(endS)
    expect(events).toHaveLength(3)
    expect(events[0]).toMatchObject({ event: 'access.summary', result: 'denied', actor: { type: 'anonymous' }, target: { type: 'host', id: 'kuma' } })
    expect(events[1]).toMatchObject({ result: 'success', actor: { type: 'user', id: ANA } })
    expect(events[1].changes?.summary).toBe('echo: 40 requests allowed, 2 denied, 2026-09-28 11:00–12:00 UTC')
    expect(events[2]).toMatchObject({ actor: { type: 'service', id: 'ci-deployer' } })
    for (const e of events) expect(auditEventV1Schema.safeParse(buildEvent(e)).success).toBe(true)
    expect(loki.queries[0]).toContain('[3600s]')
  })

  it('at most 200 events an hour: the rest folded into one per kind, so the totals still add up', async () => {
    loki.samples = Array.from({ length: 250 }, (_, i) => sample(true, `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`, 'echo', 1000 - i))
    const events = await hourEvents(endS)
    expect(events).toHaveLength(201)
    expect(events[200]).toMatchObject({ actor: { type: 'user' } })
    expect(events[200].changes?.summary).toMatch(/^50 more user\/host pairs: \d+ requests allowed/)
  })

  it('each closed hour is written once across replicas, and an hour Loki could not answer is given back', async () => {
    loki.samples = [sample(true, BOB, 'echo', 1)]
    const now = Date.UTC(2026, 8, 28, 12, 10)
    expect(await rollupTick(now)).toHaveLength(3)
    expect(await rollupTick(now)).toHaveLength(0)
    expect(h.emitted).toHaveLength(3)
    loki.down = true
    const later = Date.UTC(2026, 8, 28, 13, 10)
    expect(await rollupTick(later)).toHaveLength(0)
    loki.down = false
    expect(await rollupTick(later)).toEqual([Date.UTC(2026, 8, 28, 13) / 1000])
  })
})
