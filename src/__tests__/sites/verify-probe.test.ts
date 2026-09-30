import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

const m = vi.hoisted(() => ({ env: { OPA_URL: 'http://opa:8181', OPA_TOKEN: 't0k' } as Record<string, string | undefined> }))
vi.mock('../../config/env.js', () => ({ env: m.env }))

import { PROBE_MAX_ROUTES, curlFor, judge, probeMethod, probeRoutes, setProbeTransport, type ProbeTarget } from '../../sites/verify-probe.js'
import { PROBE_ORG, objectPath } from '../../sites/verify-access.js'
import { queryOpaAdhoc, OpaQueryError, OpaUnavailableError } from '../../services/opa-client.js'

// The outside view of a published site (sites/verify-probe.ts) and the policy question behind the
// access matrix (verify-access.ts, opa-client queryOpaAdhoc).

const target = (over: Partial<ProbeTarget> = {}): ProbeTarget => ({ route: 'r', methods: ['GET'], path: '/api/x', access: { kind: 'permission', permission: 'x:read' }, ...over })

describe('judge', () => {
  it.each([
    ['protected', 401, null, 'ok'],
    ['protected', 403, null, 'ok'],
    ['protected', 302, 'https://login.dev.example.com/self-service/login/browser?return_to=x', 'ok'],
    ['protected', 302, 'https://elsewhere.example.com/', 'unexpected'],
    ['protected', 200, null, 'exposed'],
    ['protected', 204, null, 'exposed'],
    ['protected', 404, null, 'unexpected'],
    ['public', 200, null, 'ok'],
    ['public', 301, 'https://x/', 'ok'],
    ['public', 401, null, 'unexpected'],
    ['public', 500, null, 'unexpected'],
    ['denied', 404, null, 'ok'],
    ['denied', 200, null, 'exposed'],
  ] as const)('%s answered %i (%s) → %s', (expect_, status, location, verdict) => {
    expect(judge(expect_, status, location).verdict).toBe(verdict)
  })

  it('only an anonymous 2xx on a protected route is an error', () => {
    expect(judge('protected', 200, null).level).toBe('error')
    expect(judge('public', 401, null).level).toBe('warn')
  })
})

describe('probeMethod', () => {
  it('GET, else HEAD, else the first method — never a write to a public route', () => {
    expect(probeMethod(target({ methods: ['POST', 'GET'] }))).toBe('GET')
    expect(probeMethod(target({ methods: ['HEAD', 'POST'] }))).toBe('HEAD')
    expect(probeMethod(target({ methods: ['DELETE'] }))).toBe('DELETE')
    expect(probeMethod(target({ methods: ['POST'], access: { kind: 'public' } }))).toBeNull()
  })
})

describe('probeRoutes', () => {
  afterEach(() => setProbeTransport(null))

  it('sequential, at most PROBE_MAX_ROUTES, the rest listed as not probed; a public write is skipped', async () => {
    let inFlight = 0
    let most = 0
    const urls: string[] = []
    setProbeTransport({
      async request(_m, url) {
        inFlight++
        most = Math.max(most, inFlight)
        await new Promise((r) => setTimeout(r, 1))
        inFlight--
        urls.push(url)
        return { status: 401, location: null }
      },
      async tls() { return { authorized: true, validTo: null, error: null } },
    })
    const targets = [target({ route: 'signup', methods: ['POST'], access: { kind: 'public' } }), ...Array.from({ length: 59 }, (_, i) => target({ route: `r${i}`, path: `/r/${i}/:id` }))]
    const report = await probeRoutes('a.example.com', targets)
    expect(most).toBe(1)
    expect(report.results).toHaveLength(PROBE_MAX_ROUTES)
    expect(report.results[0]).toMatchObject({ route: 'signup', verdict: 'skipped', status: null })
    expect(urls).toHaveLength(PROBE_MAX_ROUTES - 1)
    expect(urls[0]).toBe('https://a.example.com/r/0/x1')
    expect(report.notProbed).toEqual(Array.from({ length: 10 }, (_, i) => `r${49 + i}`))
  })

  it('stops at the time budget: a probe that could run past it is not sent, the rest are listed', async () => {
    let now = 0
    const sent: string[] = []
    setProbeTransport({
      async request(_m, url) { sent.push(url); now += 4000; return { status: 401, location: null } },
      async tls() { return { authorized: true, validTo: null, error: null } },
    })
    const targets = Array.from({ length: 10 }, (_, i) => target({ route: `r${i}`, path: `/r/${i}` }))
    const report = await probeRoutes('a.example.com', targets, 20_000, () => now)
    // 0, 4, 8, 12 s start a probe (each may take 5 s); at 16 s one more could end past 20 s.
    expect(sent).toHaveLength(4)
    expect(report).toMatchObject({ available: true, stoppedBy: 'budget', notProbed: ['r4', 'r5', 'r6', 'r7', 'r8', 'r9'] })
  })

  it('a failure after the first answer is one unreachable route, not an unavailable probe', async () => {
    let n = 0
    setProbeTransport({
      async request() { if (n++ === 1) throw Object.assign(new Error('x'), { name: 'TimeoutError' }); return { status: 401, location: null } },
      async tls() { return { authorized: true, validTo: null, error: null } },
    })
    const report = await probeRoutes('a.example.com', [target({ route: 'a' }), target({ route: 'b' }), target({ route: 'c' })])
    expect(report.available).toBe(true)
    expect(report.results.map((r) => r.verdict)).toEqual(['ok', 'unreachable', 'ok'])
    expect(report.results[1].message).toBe('no answer (timeout)')
  })
})

describe('curlFor and objectPath', () => {
  it('a GET needs no -X; the token variant adds the Authorization header placeholder', () => {
    expect(curlFor('a.example.com', target({ path: '/files/:any*' }))).toEqual({
      route: 'r', method: 'GET', url: 'https://a.example.com/files/probe/x',
      anonymous: "curl -sS -o /dev/null -w '%{http_code}\\n' 'https://a.example.com/files/probe/x'",
      withToken: "curl -sS -o /dev/null -w '%{http_code}\\n' 'https://a.example.com/files/probe/x' -H \"Authorization: Bearer $TOKEN\"",
    })
  })

  it('the org segment names the synthetic caller\'s organization', () => {
    expect(objectPath('/api/orgs/:orgId/items/:id', 'orgId')).toBe(`/api/orgs/${PROBE_ORG}/items/x1`)
    expect(objectPath('/api/items/:id')).toBe('/api/items/x1')
  })
})

describe('queryOpaAdhoc', () => {
  beforeEach(() => { m.env.OPA_URL = 'http://opa:8181/'; m.env.OPA_TOKEN = 't0k' })
  afterEach(() => vi.unstubAllGlobals())

  it('POST /v1/query with the token; answers the first result\'s x', async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ result: [{ x: { a: 1 } }] }), { status: 200 }))
    vi.stubGlobal('fetch', fetch)
    expect(await queryOpaAdhoc('x := 1', { cases: {} })).toEqual({ a: 1 })
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('http://opa:8181/v1/query')
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer t0k')
    expect(JSON.parse(init.body as string)).toEqual({ query: 'x := 1', input: { cases: {} } })
  })

  it('unconfigured → OpaUnavailableError; refused → OpaQueryError without the token', async () => {
    m.env.OPA_TOKEN = undefined
    await expect(queryOpaAdhoc('x := 1', {})).rejects.toBeInstanceOf(OpaUnavailableError)
    m.env.OPA_TOKEN = 't0k'
    vi.stubGlobal('fetch', vi.fn(async () => new Response('no', { status: 403 })))
    const err = await queryOpaAdhoc('x := 1', {}).catch((e) => e)
    expect(err).toBeInstanceOf(OpaQueryError)
    expect(err.message).not.toContain('t0k')
  })
})
