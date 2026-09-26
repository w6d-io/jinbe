import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import { FakeLoki, MemoryRedis, line } from './mocks.js'

// AUD-9: /api/audit/* per audit-tab.md §4.4. jinbe builds every query; the caller's scope is
// injected server-side (AU-3, AU-4); windows and limits are enforced before Loki is asked; and an
// unreachable store is a 503, never an empty list (AU-11).

const h = vi.hoisted(() => ({
  platform: new Set<string>(['root']),
  admins: { 'org-admin-a': ['org-a'], 'org-admin-ab': ['org-a', 'org-b'] } as Record<string, string[]>,
  members: { 'user-in-a': ['org-a'], 'user-in-b': ['org-b'] } as Record<string, string[]>,
  emit: vi.fn(async () => '1-0'),
  redis: null as unknown,
}))

// The scope is OPA's: what the caller holds in jinbe, and the orgs they administer (roster ∧ member).
const who = (email: string) => email.split('@')[0]
vi.mock('../../../authz/opa.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../authz/opa.js')>()),
  rights: vi.fn(async (email: string) => {
    if (who(email) === 'broken') throw new Error('OPA is unreachable')
    return { groups: [], roles: [], permissions: h.platform.has(who(email)) ? ['admin:read'] : [] }
  }),
  manageableOrgs: vi.fn(async (email: string) => h.admins[who(email)] ?? []),
}))
vi.mock('../../../services/organisation-store.js', () => ({
  organisationsForSubject: vi.fn(async (id: string) => h.members[id] ?? []),
}))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../../services/redis-client.service.js', async () => {
  const { MemoryRedis } = await import('./mocks.js')
  h.redis = new MemoryRedis()
  return { getRedisClient: () => h.redis }
})

import { setLokiClient } from '../../../audit/query/loki.js'
import { auditApiRoutes } from '../../../routes/audit-api.routes.js'
import { drainExports, exportsConfig } from '../../../audit/query/exports.js'
import { declaredRoutes, resetDeclaredRoutes } from '../../../policy/declared-routes.js'
import { tailConfig } from '../../../audit/query/tail.js'

const loki = new FakeLoki()
const DAY = 86_400_000
const NOW = Date.now()
const iso = (ms: number) => new Date(ms).toISOString()
const week = `from=${iso(NOW - 7 * DAY)}&to=${iso(NOW)}`

let app: FastifyInstance
beforeAll(async () => {
  setLokiClient(loki)
  exportsConfig.autoDrain = false
  resetDeclaredRoutes()
  app = Fastify()
  app.addHook('onRequest', async (request) => {
    const id = request.headers['x-test-subject'] as string | undefined
    if (id) request.userContext = { id, email: `${id}@example.com`, name: id }
  })
  await app.register(auditApiRoutes, { prefix: '/api/audit' })
  await app.ready()
})
afterAll(async () => { await app.close(); setLokiClient(null) })

beforeEach(() => {
  loki.down = false
  loki.queries = []
  loki.ranges = []
  loki.entries = [
    line({ event: 'org.grants.changed', org_id: 'org-a', actor: { id: 'org-admin-a' }, target: { type: 'user', id: 'user-in-a' } }, NOW - 3 * DAY),
    line({ event: 'org.member.added', org_id: 'org-b', target: { type: 'user', id: 'user-in-b' } }, NOW - 2 * DAY),
    line({ event: 'config.auth_methods.changed', org_id: null }, NOW - DAY),
    line({ event: 'auth.login.succeeded', actor: { id: 'user-in-a' }, target: { type: 'user', id: 'user-in-a' }, org_id: null }, NOW - 1000),
  ]
  h.emit.mockClear()
})

const get = (url: string, subject = 'root') => app.inject({ method: 'GET', url, headers: { 'x-test-subject': subject } })

describe('GET /api/audit/events — shape (§4.4)', () => {
  it('answers events, nextCursor, scope, range, truncated, source and queryMs', async () => {
    const res = await get(`/api/audit/events?${week}`)
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(Object.keys(body).sort()).toEqual(['events', 'nextCursor', 'queryMs', 'range', 'scope', 'source', 'truncated'])
    expect(body.scope).toEqual({ orgs: [], platform: true })
    expect(body.source).toBe('loki')
    expect(body.truncated).toBe(false)
    expect(body.events).toHaveLength(4)
    // Newest first, as audit/v1 events — the logger's own fields stripped.
    expect(body.events[0].event).toBe('auth.login.succeeded')
    expect(body.events[0]).not.toHaveProperty('hostname')
    expect(body.events[0]).toHaveProperty('event_id')
    expect(loki.queries[0].startsWith('{log_type="audit"}')).toBe(true)
  })

  it('pages with an opaque cursor and never repeats an event', async () => {
    const first = (await get(`/api/audit/events?${week}&limit=2`)).json()
    expect(first.events).toHaveLength(2)
    expect(first.nextCursor).toEqual(expect.any(String))
    const second = (await get(`/api/audit/events?${week}&limit=2&cursor=${encodeURIComponent(first.nextCursor)}`)).json()
    expect(second.events).toHaveLength(2)
    const ids = [...first.events, ...second.events].map((e: { event_id: string }) => e.event_id)
    expect(new Set(ids).size).toBe(4)
    // Nothing older in the window: the cursor says so rather than sending the UI to an empty page.
    expect(second.nextCursor).toBeNull()
  })

  it('refuses a forged cursor', async () => {
    expect((await get(`/api/audit/events?${week}&cursor=not-a-cursor`)).statusCode).toBe(400)
  })
})

describe('windows and limits are enforced before Loki is asked', () => {
  it('requires from and to', async () => {
    expect((await get('/api/audit/events')).statusCode).toBe(400)
  })
  it('refuses more than 30 days per page', async () => {
    const res = await get(`/api/audit/events?from=${iso(NOW - 31 * DAY)}&to=${iso(NOW)}`)
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toBe('range_too_large')
    expect(loki.queries).toHaveLength(0)
  })
  it('refuses a lookback past 400 days', async () => {
    const res = await get(`/api/audit/events?from=${iso(NOW - 410 * DAY)}&to=${iso(NOW - 405 * DAY)}`)
    expect(res.statusCode).toBe(400)
  })
  it('refuses limit > 200 and a free text over 64 characters', async () => {
    expect((await get(`/api/audit/events?${week}&limit=201`)).statusCode).toBe(400)
    expect((await get(`/api/audit/events?${week}&q=${'x'.repeat(65)}`)).statusCode).toBe(400)
  })
  it('refuses a facet outside the allow-list', async () => {
    expect((await get(`/api/audit/events?${week}&result=maybe`)).statusCode).toBe(400)
    expect((await get(`/api/audit/events?${week}&event=${encodeURIComponent('x"} |= "')}`)).statusCode).toBe(400)
    expect((await get(`/api/audit/events?${week}&logql=${encodeURIComponent('{app="x"}')}`)).statusCode).toBe(400)
  })
  it('asks Loki for at most limit+1 entries inside the window', async () => {
    await get(`/api/audit/events?${week}&limit=50`)
    expect(loki.ranges[0].limit).toBeLessThanOrEqual(5000)
    expect(loki.ranges[0].limit).toBe(51)
    expect(BigInt(loki.ranges[0].endNs) - BigInt(loki.ranges[0].startNs)).toBeLessThanOrEqual(BigInt(30 * DAY + 1) * 1_000_000n)
  })
  it('the free text goes in escaped (AU-12)', async () => {
    await get(`/api/audit/events?${week}&q=${encodeURIComponent('"} |= "')}`)
    expect(loki.queries[0]).toContain('|= "\\"} |= \\""')
  })
})

describe('org scoping (AU-3, AU-4)', () => {
  it('AU-3: an org admin asking for another org gets 403', async () => {
    const res = await get(`/api/audit/events?${week}&org=org-b`, 'org-admin-a')
    expect(res.statusCode).toBe(403)
    expect(loki.queries).toHaveLength(0)
  })

  it('AU-4: an org admin with no org filter is forced to their own org, server-side', async () => {
    const res = await get(`/api/audit/events?${week}`, 'org-admin-a')
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.scope).toEqual({ orgs: ['org-a'], platform: false })
    expect(loki.queries[0]).toContain('org_id="org-a"')
    // Even if the store answered more, nothing foreign reaches the caller.
    expect(body.events.map((e: { org_id: string }) => e.org_id)).toEqual(['org-a'])
  })

  it('an admin of two orgs sees both and nothing else', async () => {
    const body = (await get(`/api/audit/events?${week}`, 'org-admin-ab')).json()
    expect(body.scope.orgs).toEqual(['org-a', 'org-b'])
    expect(body.events.map((e: { org_id: string }) => e.org_id).sort()).toEqual(['org-a', 'org-b'])
  })

  it('a member who administers nothing gets 403', async () => {
    expect((await get(`/api/audit/events?${week}`, 'nobody')).statusCode).toBe(403)
  })

  it('super_admin / admin:read sees every org, and platform events', async () => {
    const body = (await get(`/api/audit/events?${week}&org=org-b`)).json()
    expect(body.events.map((e: { event: string }) => e.event)).toEqual(['org.member.added'])
  })

  it('unauthenticated → 401; model unreadable → 503', async () => {
    expect((await app.inject({ method: 'GET', url: `/api/audit/events?${week}` })).statusCode).toBe(401)
    expect((await get(`/api/audit/events?${week}`, 'broken')).statusCode).toBe(503)
  })
})

describe('Loki down → 503, never an empty list (AU-11)', () => {
  it.each([`/api/audit/events?${week}`, `/api/audit/facets?${week}`, '/api/audit/summary?window=24h', `/api/audit/me/logins?${week}`, `/api/audit/users/user-in-a/timeline?${week}`])('%s', async (url) => {
    loki.down = true
    const res = await get(url)
    expect(res.statusCode).toBe(503)
    expect(res.json()).toEqual({ error: 'audit_store_unavailable' })
  })
})

describe('facets, summary, event by id, timeline, me/logins', () => {
  it('facets: counts per event/category/result/site/actor for the whole range', async () => {
    loki.samples = [{ metric: { event: 'org.grants.changed' }, value: 3 }]
    const body = (await get(`/api/audit/facets?${week}`)).json()
    expect(Object.keys(body.facets).sort()).toEqual(['actor', 'category', 'event', 'result', 'site'])
    expect(body.facets.event[0]).toEqual({ key: 'org.grants.changed', count: 3 })
    expect(loki.queries.some((q) => q.includes('sum by (event)') && q.includes('count_over_time'))).toBe(true)
  })

  it('summary: window label is a string, with prev and series', async () => {
    loki.samples = [{ metric: { result: 'success' }, value: 5 }]
    loki.series = [{ metric: { result: 'success' }, values: [[NOW / 1000, 5]] }]
    const res = await get('/api/audit/summary?window=24h')
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.window).toBe('24h')
    for (const k of ['total', 'prev', 'byCategory', 'byResult', 'series', 'topDenied', 'topActors', 'scope']) expect(body).toHaveProperty(k)
    expect(body.series[0]).toMatchObject({ total: 5, failed: 0 })
    expect((await get('/api/audit/summary?window=31d')).statusCode).toBe(400)
  })

  it('event by id: the event and its chain status', async () => {
    const target = JSON.parse(loki.entries[1].line)
    const body = (await get(`/api/audit/events/${target.event_id}?ts=${encodeURIComponent(target.ts)}`)).json()
    expect(body.event.event_id).toBe(target.event_id)
    expect(body.chain).toBe('verified')
  })

  it('event by id: an edited line reads broken', async () => {
    const tampered = JSON.parse(loki.entries[1].line)
    tampered.org_id = 'org-z'
    loki.entries[1] = { ...loki.entries[1], line: JSON.stringify(tampered) }
    const body = (await get(`/api/audit/events/${tampered.event_id}`)).json()
    expect(body.chain).toBe('broken')
  })

  it('event by id: out of an org admin\'s scope is 404', async () => {
    const other = JSON.parse(loki.entries[1].line)
    expect((await get(`/api/audit/events/${other.event_id}`, 'org-admin-a')).statusCode).toBe(404)
  })

  it('user timeline: an org admin may read a member of their org, not anyone else', async () => {
    expect((await get(`/api/audit/users/user-in-a/timeline?${week}`, 'org-admin-a')).statusCode).toBe(200)
    expect(loki.queries.at(-1)).toContain('actor_id="user-in-a" or target_id="user-in-a"')
    expect(loki.queries.at(-1)).toContain('org_id="org-a"')
    expect((await get(`/api/audit/users/user-in-b/timeline?${week}`, 'org-admin-a')).statusCode).toBe(403)
  })

  it('me/logins: any authenticated user, their own auth events only', async () => {
    const res = await get(`/api/audit/me/logins?${week}`, 'user-in-a')
    expect(res.statusCode).toBe(200)
    expect(loki.queries.at(-1)).toContain('actor_id="user-in-a" or target_id="user-in-a"')
    expect(loki.queries.at(-1)).toContain('event=~"auth\\\\..*"')
    expect(res.json().events.map((e: { event: string }) => e.event)).toEqual(['auth.login.succeeded'])
  })
})

describe('exports (async, outbox-style) and saved queries', () => {
  it('POST → 202 {id}; the job runs, is audited once, and serves CSV to its owner only', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/audit/exports', headers: { 'x-test-subject': 'root' }, payload: { from: iso(NOW - 7 * DAY), to: iso(NOW), format: 'csv', filters: {} } })
    expect(res.statusCode).toBe(202)
    const { id } = res.json()
    await drainExports()
    const status = (await get(`/api/audit/exports/${id}`)).json()
    expect(status).toMatchObject({ id, status: 'done', rows: 4, format: 'csv', url: `/api/audit/exports/${id}/download` })
    expect(status.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(h.emit).toHaveBeenCalledTimes(1)
    expect((h.emit.mock.calls[0] as unknown as [Record<string, unknown>])[0]).toMatchObject({ v1Event: 'audit.exported' })
    const file = await get(`/api/audit/exports/${id}/download`)
    expect(file.headers['content-type']).toContain('text/csv')
    expect(file.body.split('\n')[0]).toContain('event_id')
    expect((await get(`/api/audit/exports/${id}`, 'org-admin-a')).statusCode).toBe(404)
  })

  it('one export at a time per user; Loki down marks the job failed', async () => {
    const post = () => app.inject({ method: 'POST', url: '/api/audit/exports', headers: { 'x-test-subject': 'org-admin-ab' }, payload: { from: iso(NOW - DAY), to: iso(NOW), format: 'ndjson' } })
    const first = await post()
    expect(first.statusCode).toBe(202)
    expect((await post()).statusCode).toBe(429)
    loki.down = true
    await drainExports()
    expect((await get(`/api/audit/exports/${first.json().id}`, 'org-admin-ab')).json()).toMatchObject({ status: 'failed', error: 'audit_store_unavailable' })
    expect((await post()).statusCode).toBe(202) // the lock was released
  })

  it('saved queries: create, list (own + shared in scope), delete own only', async () => {
    const create = await app.inject({ method: 'POST', url: '/api/audit/saved-queries', headers: { 'x-test-subject': 'org-admin-a' }, payload: { name: 'Denied', filters: { result: 'denied' }, shared: true, orgId: 'org-a' } })
    expect(create.statusCode).toBe(201)
    const saved = create.json()
    expect(saved).toMatchObject({ name: 'Denied', filters: { result: 'denied' }, shared: true, orgId: 'org-a' })
    expect((await app.inject({ method: 'POST', url: '/api/audit/saved-queries', headers: { 'x-test-subject': 'org-admin-a' }, payload: { name: 'x', filters: {}, shared: true, orgId: 'org-b' } })).statusCode).toBe(403)
    expect((await get('/api/audit/saved-queries', 'org-admin-ab')).json().queries.map((q: { id: string }) => q.id)).toContain(saved.id)
    expect((await app.inject({ method: 'DELETE', url: `/api/audit/saved-queries/${saved.id}`, headers: { 'x-test-subject': 'org-admin-ab' } })).statusCode).toBe(404)
    expect((await app.inject({ method: 'DELETE', url: `/api/audit/saved-queries/${saved.id}`, headers: { 'x-test-subject': 'org-admin-a' } })).statusCode).toBe(204)
  })
})

describe('GET /api/audit/tail (SSE)', () => {
  it('Loki down → 503 before any stream opens', async () => {
    loki.down = true
    expect((await get('/api/audit/tail')).statusCode).toBe(503)
  })

  it('streams scoped events, then ends at the maximum duration and frees the lock', async () => {
    tailConfig.maxMs = 60
    tailConfig.pollMs = 10
    loki.entries.push(line({ event: 'org.grants.changed', org_id: 'org-b' }, Date.now() + 5), line({ event: 'org.grants.changed', org_id: 'org-a' }, Date.now() + 6))
    const res = await get('/api/audit/tail', 'org-admin-a')
    expect(res.statusCode).toBe(200)
    expect(res.headers['content-type']).toContain('text/event-stream')
    const events = res.body.split('\n\n').filter((b) => b.startsWith('event: audit')).map((b) => JSON.parse(b.split('data: ')[1]))
    expect(events.map((e: { org_id: string }) => e.org_id)).toEqual(['org-a'])
    expect(res.body).toContain('event: end')
    expect((h.redis as MemoryRedis).kv.has('auth:audit:tail:org-admin-a')).toBe(false)
  })
})

describe('guards are declared in the route table', () => {
  it('every /api/audit route carries a guard, me/logins only needs a session', () => {
    const rows = declaredRoutes().filter((r) => r.path.startsWith('/api/audit'))
    expect(rows.length).toBeGreaterThanOrEqual(12)
    for (const r of rows) {
      if (r.path === '/api/audit/me/logins') expect(r.class).toBe('authenticated')
      else expect(r, `${r.method} ${r.path}`).toMatchObject({ class: 'authorized' })
    }
  })
})
