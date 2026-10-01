import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import { installRouteAccess } from '../../policy/route-access.js'
import { ACK, payrollSite } from './fixtures.js'
import { fakeGatekit } from './mocks.js'
import { fakeCluster } from './harness.js'

// Guided site onboarding over HTTP: a gate that lets nobody in is refused on every write (422), the
// check endpoint (preview) carries the security findings, publishing refuses unconfirmed findings
// (apply and the apply request), and POST /:name/verify reports what is really served.

const h = vi.hoisted(() => ({
  gatekit: {
    compile: (patterns: Array<{ id: string }>) => ({ results: patterns.map((p) => ({ id: p.id, ok: true })) }) as unknown,
    overlap: (_b: unknown) => ({ overlaps: [] }) as unknown,
    status: 200,
    calls: [] as Array<{ path: string; body: Record<string, unknown> }>,
  },
  opa: vi.fn(),
}))

vi.mock('../../services/redis-client.service.js', async () => {
  const { InlineRedisMock } = await import('./mocks.js')
  const redis = new InlineRedisMock()
  return { getRedisClient: () => redis, __redis: redis }
})
vi.mock('../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => Promise<unknown>) => fn() }))
vi.mock('../../services/redis-rbac.repository.js', async () => {
  const { makeRbacStore } = await import('./mocks.js')
  const store = makeRbacStore()
  return { redisRbacRepository: store.repo, __store: store }
})
vi.mock('../../services/rbac.service.js', () => ({ rbacService: { invalidateBundle: vi.fn() } }))
vi.mock('../../services/org-grants.repository.js', () => ({ orgGrantsRepository: { getAll: vi.fn(async () => ({})) } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn() } }))
vi.mock('../../services/opa-client.js', async (importOriginal) => ({ ...(await importOriginal<typeof import('../../services/opa-client.js')>()), queryOpaAdhoc: h.opa }))
vi.mock('../../middleware/require-permission.js', async () => (await import('../helpers/permission-stand-ins.js')).permissionStandIn())
vi.mock('../../middleware/require-admin.js', async () => (await import('../helpers/permission-stand-ins.js')).adminStandIn())

import { sitesRoutes } from '../../sites/routes.js'
import { setKubeSites } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import { setDnsLookup } from '../../sites/dns-probe.js'
import { setProbeTransport, type ProbeTransport } from '../../sites/verify-probe.js'
import { resetVerifyLimiter } from '../../sites/verify.js'
import { PROBE_EMAIL, PROBE_ORG } from '../../sites/verify-access.js'
import { declaredRoutes, resetDeclaredRoutes } from '../../policy/declared-routes.js'
import * as redisClient from '../../services/redis-client.service.js'
import * as rbacRepo from '../../services/redis-rbac.repository.js'

type Store = ReturnType<typeof import('./mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('./mocks.js').InlineRedisMock }).__redis
const cluster = fakeCluster()

let app: FastifyInstance
const W = { 'x-test-write': '1' }
const WM = { 'x-test-write': '1', 'x-test-mfa': '1' }

/** The web answers: protected routes 401, public ones 200 — unless a test says otherwise. */
const web = {
  answers: {} as Record<string, number>,
  requests: [] as Array<{ method: string; url: string }>,
  down: false,
  tls: { authorized: true, validTo: new Date(Date.now() + 60 * 86_400_000).toISOString(), error: null } as Awaited<ReturnType<ProbeTransport['tls']>>,
}
const transport: ProbeTransport = {
  async request(method, url) {
    web.requests.push({ method, url })
    if (web.down) throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } })
    const path = new URL(url).pathname
    if (url.includes('jinbe_verify=')) return { status: web.answers.waf ?? 403, location: null }
    return { status: web.answers[path] ?? (path === '/health' ? 200 : 401), location: null }
  },
  async tls() { return web.tls },
}

beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => { request.userContext = { id: 'sam-id', email: 'sam@x.test', name: 'Sam' } })
  await app.register(sitesRoutes, { prefix: '/sites' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  redis.clear()
  store.reset()
  cluster.reset()
  h.opa.mockReset()
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_KUBE = 'off'
  process.env.SITES_ZONES = '[{"suffix":"dev.example.com","wildcardTls":true,"exposure":"ingress"}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.example.com'
  process.env.SITES_RESERVED_HOSTS = 'kuma.dev.example.com'
  resetSitesConfig()
  setKubeSites(cluster.kube)
  vi.stubGlobal('fetch', fakeGatekit(h.gatekit))
  setDnsLookup({ addresses: async (name) => (name === 'payroll.dev.example.com' ? ['203.0.113.7'] : []) })
  setProbeTransport(transport)
  resetVerifyLimiter()
  web.answers = {}
  web.requests = []
  web.down = false
})

const save = (site: unknown = payrollSite()) => app.inject({ method: 'PUT', url: '/sites/payroll', headers: W, payload: { site, note: 'v' } })
const apply = (body: Record<string, unknown>) => app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: WM, payload: { version: 1, ...body } })

describe('a gate that lets nobody in is refused on every write', () => {
  const noAuth = (authenticators: unknown) => {
    const site = payrollSite() as unknown as { gates: Array<Record<string, unknown>> }
    site.gates[0] = { ...site.gates[0], authenticators }
    if (authenticators === undefined) delete site.gates[0].authenticators
    return site
  }

  it.each([[[]], [undefined]])('draft autosave with authenticators %j → 422 gate_without_authenticator', async (authenticators) => {
    const res = await app.inject({ method: 'PUT', url: '/sites/payroll/draft', headers: W, payload: { site: noAuth(authenticators) } })
    expect(res.statusCode).toBe(422)
    expect(res.json()).toMatchObject({ error: 'gate_without_authenticator', checks: [{ code: 'gate_without_authenticator', path: 'gates.0.authenticators' }] })
    expect(redis.hashes.size + redis.strings.size).toBe(0)
  })

  it('an incomplete draft without that problem is still autosaved', async () => {
    const res = await app.inject({ method: 'PUT', url: '/sites/payroll/draft', headers: W, payload: { site: { name: 'payroll', gates: [{ id: 'web', authenticators: [{ handler: 'cookie_session' }] }] } } })
    expect(res.statusCode).toBe(200)
  })

  it('save → 422 (not a schema 400), nothing saved', async () => {
    const res = await save(noAuth([]))
    expect(res.statusCode).toBe(422)
    expect(res.json().error).toBe('gate_without_authenticator')
    expect((await app.inject({ method: 'GET', url: '/sites/payroll' })).statusCode).toBe(404)
  })

  it('a bulk route mapping onto a draft with such a gate is refused at commit', async () => {
    const { sitesRoutesUpsert } = await import('../../bulk/ops/sites.js')
    const actor = { id: null, email: 'sam@x.test', ip: null, ua: null, sessionId: null, requestId: null }
    const state = { site: noAuth([]) as never, baseVersion: 0, changed: 1 }
    await expect(sitesRoutesUpsert.commit!({ siteActor: actor } as never, { site: 'payroll' }, state as never, { jobId: 'j' } as never)).rejects.toMatchObject({ statusCode: 422, code: 'gate_without_authenticator' })
  })
})

describe('the check endpoint (preview) carries the security findings', () => {
  it('findings with code, level, message, fix and path, and what publishing needs', async () => {
    const res = await app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site: payrollSite() } })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.findings).toEqual(expect.arrayContaining([
      { code: 'public_route', level: 'confirm', message: 'GET /health is open to anyone, without signing in', fix: expect.any(String), path: 'routes.items.0' },
      expect.objectContaining({ code: 'signed_in_catch_all', level: 'confirm', path: 'routes.catchAll' }),
      expect.objectContaining({ code: 'waf_off', level: 'warn', message: expect.stringContaining('nginx Ingress') }),
    ]))
    expect(body.publish).toEqual({ blocked: false, acknowledge: ['public_route', 'signed_in_catch_all'] })
  })

  it('a check apply refuses on (unknown platform group) is an error finding: blocked, and apply still 409s', async () => {
    const site = payrollSite({ groups: { platform: { 'no-such-group': ['viewer'] }, orgGrantable: payrollSite().groups.orgGrantable } })
    const body = (await app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site } })).json()
    expect(body.findings).toContainEqual({
      code: 'unknown_group', level: 'error', message: "platform group 'no-such-group' does not exist",
      fix: expect.stringContaining('Create the group first'), path: 'groups.platform.no-such-group',
    })
    expect(body.publish.blocked).toBe(true)
    expect(body.checks).toContainEqual(expect.objectContaining({ code: 'unknown_group', level: 'error' }))
    // Apply's own checks stay the backstop.
    await save(site)
    const res = await apply({ acknowledge: [...ACK, 'unknown_group'] })
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toBe('checks_failed')
  })

  it('a gatekit overlap is an error finding too', async () => {
    h.gatekit.overlap = (body: unknown) => {
      const ids = (body as { rules: Array<{ id: string }> }).rules.map((r) => r.id)
      return { overlaps: [{ a: ids[0], b: ids[1], method: 'GET', exampleUrl: 'https://payroll.dev.example.com/health' }] }
    }
    const body = (await app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site: payrollSite() } })).json()
    h.gatekit.overlap = () => ({ overlaps: [] })
    expect(body.findings).toContainEqual(expect.objectContaining({ code: 'rule_overlap', level: 'error', fix: expect.stringContaining('POST /sites/match') }))
    expect(body.publish.blocked).toBe(true)
  })

  it('the simulation-api gate is reported: not a preset, bare bearer_token', async () => {
    const site = payrollSite()
    site.gates[0] = { ...site.gates[0], authenticators: [{ handler: 'cookie_session' }, { handler: 'bearer_token' }] }
    const body = (await app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site } })).json()
    expect(body.findings.map((f: { code: string }) => f.code)).toEqual(expect.arrayContaining(['gate_not_preset', 'bare_bearer_token']))
  })
})

describe('publishing refuses unconfirmed findings', () => {
  it('apply without acknowledge → 422 unconfirmed_findings listing them; nothing published', async () => {
    await save()
    const res = await apply({})
    expect(res.statusCode).toBe(422)
    expect(res.json()).toMatchObject({ error: 'unconfirmed_findings', message: expect.stringContaining('"public_route"') })
    expect(res.json().findings.map((f: { code: string }) => f.code)).toEqual(['public_route', 'signed_in_catch_all'])
    expect(cluster.kube.applied).toEqual([])
    expect(store.s.log).toEqual([])
  })

  it('a partial acknowledgement lists only what is left; the full one publishes and is audited', async () => {
    await save()
    const partial = await apply({ acknowledge: ['public_route'] })
    expect(partial.statusCode).toBe(422)
    expect(partial.json().findings.map((f: { code: string }) => f.code)).toEqual(['signed_in_catch_all'])
    const ok = await apply({ acknowledge: ['public_route', 'signed_in_catch_all'] })
    expect(ok.statusCode).toBe(200)
    expect(cluster.kube.applied).toHaveLength(1)
  })

  it('an error finding blocks even when acknowledged', async () => {
    const site = payrollSite()
    // noop first on a policy gate: the policy has nobody to check (only cookie_session and noop are enabled here).
    site.gates[0] = { ...site.gates[0], authenticators: [{ handler: 'noop' }] }
    expect((await save(site)).statusCode).toBe(200)
    const res = await apply({ acknowledge: [...ACK, 'noop_with_policy'] })
    expect(res.statusCode).toBe(422)
    expect(res.json().findings).toEqual([expect.objectContaining({ code: 'noop_with_policy', level: 'error' })])
  })

  it('an unknown field or a malformed code is a 400', async () => {
    await save()
    expect((await apply({ acknowledge: ['Public Route'] })).statusCode).toBe(400)
  })

  it('the step-up rule is unchanged: no recent second factor is still 422 reauth_required first', async () => {
    await save()
    const res = await app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: W, payload: { version: 1, acknowledge: ACK } })
    expect(res.json().error).toBe('reauth_required')
  })

  it('an apply request is refused the same way, keeps its acknowledgements, and approval re-checks them', async () => {
    await save()
    const bare = await app.inject({ method: 'POST', url: '/sites/payroll/requests', headers: W, payload: { version: 1 } })
    expect(bare.statusCode).toBe(422)
    expect(bare.json().error).toBe('unconfirmed_findings')
    const asked = await app.inject({ method: 'POST', url: '/sites/payroll/requests', headers: W, payload: { version: 1, acknowledge: ['public_route'] } })
    expect(asked.statusCode).toBe(422)
    const req = await app.inject({ method: 'POST', url: '/sites/payroll/requests', headers: W, payload: { version: 1, acknowledge: ['public_route', 'signed_in_catch_all'] } })
    expect(req.statusCode).toBe(201)
    expect(req.json().acknowledge).toEqual(['public_route', 'signed_in_catch_all'])
    const approved = await app.inject({ method: 'POST', url: `/sites/requests/${req.json().id}/approve`, headers: WM, payload: {} })
    expect(approved.statusCode).toBe(200)
    expect(approved.json().state).toBe('applied')
  })

  it('approval refuses a finding that appeared since the request, unless the approver acknowledges it', async () => {
    await save()
    const req = await app.inject({ method: 'POST', url: '/sites/payroll/requests', headers: W, payload: { version: 1, acknowledge: ['public_route', 'signed_in_catch_all'] } })
    // As if signed_in_catch_all had appeared after the request was made: the request does not cover it.
    const redisRequests = redis.hashes.get('rbac:sites:requests')!
    const stored = JSON.parse(redisRequests.get(req.json().id)!)
    redisRequests.set(req.json().id, JSON.stringify({ ...stored, acknowledge: ['public_route'] }))
    const refused = await app.inject({ method: 'POST', url: `/sites/requests/${req.json().id}/approve`, headers: WM, payload: {} })
    expect(refused.statusCode).toBe(422)
    expect(refused.json().findings.map((f: { code: string }) => f.code)).toEqual(['signed_in_catch_all'])
    const approved = await app.inject({ method: 'POST', url: `/sites/requests/${req.json().id}/approve`, headers: WM, payload: { acknowledge: ['signed_in_catch_all'] } })
    expect(approved.statusCode).toBe(200)
  })

  it('a rollback is not gated: it puts back a version that was published already', async () => {
    await save()
    expect((await apply({ acknowledge: ACK })).statusCode).toBe(200)
    const res = await app.inject({ method: 'POST', url: '/sites/payroll/rollback', headers: WM, payload: { toVersion: 1 } })
    expect(res.statusCode).toBe(200)
  })
})

describe('POST /:name/verify', () => {
  const verify = (body: Record<string, unknown> = {}) => app.inject({ method: 'POST', url: '/sites/payroll/verify', payload: body })
  /** OPA answering `data.rbac.decision` per case: admins (and the admin role) everywhere, nobody else. */
  const opaAnswers = () => h.opa.mockImplementation(async (_query: string, input: { cases: Record<string, { membership: Record<string, string[]>; probeBinding: Record<string, string[]> }> }) =>
    Object.fromEntries(Object.entries(input.cases).map(([k, c]) => {
      const admin = (c.membership[PROBE_EMAIL] ?? []).includes('admins') || (c.probeBinding.payroll ?? []).includes('admin')
      return [k, { allow: admin, reason: admin ? 'ok' : 'forbidden' }]
    })))
  const publish = async () => {
    await save()
    expect((await apply({ acknowledge: ACK })).statusCode).toBe(200)
    cluster.operator('payroll')
  }

  it('is a sites:read route in the published route table', async () => {
    resetDeclaredRoutes()
    const admin = Fastify()
    installRouteAccess(admin)
    await admin.register(sitesRoutes, { prefix: '/api/admin/sites' })
    await admin.ready()
    expect(declaredRoutes().find((r) => r.method === 'POST' && r.path === '/api/admin/sites/:name/verify')?.permission).toBe('sites:read')
    await admin.close()
  })

  it('a site never published: the rollout says so, and nothing is sent to it', async () => {
    await save()
    const body = (await verify()).json()
    expect(body.rollout.checks[0]).toEqual({ id: 'applied', label: 'Published', status: 'fail', message: 'version 1 is saved but was never published' })
    expect(body.probe).toMatchObject({ available: false, reason: 'not published: no probe' })
    expect(body.summary.ok).toBe(false)
    expect(web.requests).toEqual([])
    expect(h.opa).not.toHaveBeenCalled()
  })

  it('a published site: rollout, one anonymous request per route, the access matrix, curl commands', async () => {
    await publish()
    opaAnswers()
    const res = await verify()
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body).toMatchObject({ site: 'payroll', host: 'payroll.dev.example.com', version: { saved: 1, applied: 1 } })
    expect(Object.fromEntries(body.rollout.checks.map((c: { id: string; status: string }) => [c.id, c.status]))).toEqual({
      applied: 'ok', site: 'ok', rules: 'ok', route: 'skipped', dns: 'ok', tls: 'ok', waf: 'warn',
    })
    expect(body.rollout.ready).toBe(true)
    expect(web.requests).toEqual([
      { method: 'GET', url: 'https://payroll.dev.example.com/health' },
      { method: 'GET', url: 'https://payroll.dev.example.com/api/orgs/x1/payslips' },
      { method: 'POST', url: 'https://payroll.dev.example.com/api/orgs/x1/payslips' },
      { method: 'GET', url: 'https://payroll.dev.example.com/probe/x' },
    ])
    expect(body.probe.results.map((r: { route: string; expect: string; status: number; verdict: string }) => [r.route, r.expect, r.status, r.verdict])).toEqual([
      ['health', 'public', 200, 'ok'], ['payslips', 'protected', 401, 'ok'], ['create', 'protected', 401, 'ok'], ['catch-all', 'protected', 401, 'ok'],
    ])
    // Org roles join the subjects once the site intent declares them (wave V4).
    expect(body.access.subjects.map((s: { key: string }) => s.key)).toEqual(['group:admins', 'role:admin', 'role:editor', 'role:viewer', 'signed-in'])
    expect(body.access.rows[1]).toEqual({
      route: 'payslips', method: 'GET', path: '/api/orgs/:orgId/payslips', access: 'payslips:read',
      answers: { 'group:admins': 'ok', 'role:admin': 'ok', 'role:editor': 'forbidden', 'role:viewer': 'forbidden', 'signed-in': 'forbidden' },
    })
    // One query for the whole matrix, about a synthetic caller in the route's organization, at aal2.
    expect(h.opa).toHaveBeenCalledTimes(1)
    const cases = h.opa.mock.calls[0][1].cases
    expect(Object.keys(cases)).toHaveLength(4 * 5)
    expect(cases['1:1']).toEqual({
      input: { email: PROBE_EMAIL, action: 'GET', object: `/api/orgs/${PROBE_ORG}/payslips`, app: 'payroll', aal: 'aal2' },
      membership: { [PROBE_EMAIL]: ['site_verify_probe'] }, probeBinding: { payroll: ['admin'] }, orgs: { [PROBE_EMAIL]: [PROBE_ORG] },
      assignments: {}, entitled: ['jinbe', 'payroll'],
    })
    expect(body.curl[2]).toEqual({
      route: 'create', method: 'POST', url: 'https://payroll.dev.example.com/api/orgs/x1/payslips',
      anonymous: "curl -sS -o /dev/null -w '%{http_code}\\n' -X POST 'https://payroll.dev.example.com/api/orgs/x1/payslips'",
      withToken: "curl -sS -o /dev/null -w '%{http_code}\\n' -X POST 'https://payroll.dev.example.com/api/orgs/x1/payslips' -H \"Authorization: Bearer $TOKEN\"",
    })
    expect(body.waf).toBeNull()
    expect(body.summary).toMatchObject({ ok: true, errors: [] })
  })

  it('a protected route answering anonymously is a security error', async () => {
    await publish()
    opaAnswers()
    web.answers['/api/orgs/x1/payslips'] = 200
    const body = (await verify()).json()
    expect(body.probe.results[1]).toMatchObject({ route: 'payslips', verdict: 'exposed', level: 'error' })
    expect(body.summary.ok).toBe(false)
    expect(body.summary.errors[0]).toContain('reachable without signing in')
  })

  it('once per site per 30 s: 429 verify_rate_limited with Retry-After', async () => {
    await publish()
    opaAnswers()
    expect((await verify()).statusCode).toBe(200)
    const again = await verify()
    expect(again.statusCode).toBe(429)
    expect(again.json().error).toBe('verify_rate_limited')
    expect(Number(again.headers['retry-after'])).toBeGreaterThan(0)
  })

  it('no egress from jinbe: probe unavailable, reported, never a failure of the call', async () => {
    await publish()
    opaAnswers()
    web.down = true
    web.tls = { authorized: false, validTo: null, error: 'ENOTFOUND' }
    const body = (await verify()).json()
    expect(body.probe).toMatchObject({ available: false, results: [], notProbed: ['health', 'payslips', 'create', 'catch-all'] })
    expect(body.probe.reason).toMatch(/^probe unavailable: jinbe could not reach https:\/\/payroll.dev.example.com\/health \(ENOTFOUND\)/)
    expect(body.rollout.checks.find((c: { id: string }) => c.id === 'tls').status).toBe('unknown')
    expect(body.curl).toHaveLength(4)
    expect(web.requests).toHaveLength(1)
    web.tls = { authorized: true, validTo: new Date(Date.now() + 60 * 86_400_000).toISOString(), error: null }
  })

  it('the WAF check only when asked: one attack-like request, 403 expected', async () => {
    await publish()
    opaAnswers()
    const blocked = (await verify({ waf: true })).json()
    expect(blocked.waf).toMatchObject({ checked: true, blocked: true, status: 403 })
    expect(web.requests.filter((r) => r.url.includes('jinbe_verify='))).toHaveLength(1)
    resetVerifyLimiter()
    web.answers.waf = 200
    const open = (await verify({ waf: true })).json()
    expect(open.waf).toMatchObject({ blocked: false, status: 200 })
    expect(open.summary.errors).toContain('WAF: an attack-like request was answered 200: the WAF did not block it')
  })

  it('OPA not answering leaves the matrix unavailable, the rest of the report intact', async () => {
    await publish()
    h.opa.mockRejectedValue(new Error('OPA refused the ad-hoc query (HTTP 403).'))
    const body = (await verify()).json()
    expect(body.access).toMatchObject({ available: false, reason: 'access matrix unavailable: OPA refused the ad-hoc query (HTTP 403).' })
    expect(body.probe.available).toBe(true)
  })

  it('a site still rolling out: pending conditions are said', async () => {
    await publish()
    opaAnswers()
    cluster.operator('payroll', { RulesLoaded: 'Pending', Ready: 'Waiting' })
    const body = (await verify()).json()
    expect(body.rollout.ready).toBe(false)
    expect(body.rollout.checks.find((c: { id: string }) => c.id === 'rules')).toMatchObject({ status: 'pending', message: expect.stringContaining('RulesLoaded is Pending') })
  })

  it('an unknown site is 404; an unknown body field 400', async () => {
    expect((await app.inject({ method: 'POST', url: '/sites/nope/verify', payload: {} })).statusCode).toBe(404)
    await save()
    expect((await verify({ probe: 'all' })).statusCode).toBe(400)
  })
})
