import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { oathkeeperRegex, payrollSite } from './fixtures.js'
import { fakeCluster } from './harness.js'
import { buildBuiltInRules } from '../../bootstrap/build-rules.js'
import type { OathkeeperRule } from '../../services/redis-rbac.repository.js'

// S-5: the one-time migration of legacy rules (rbac:oathkeeper:rules + bootstrap built-ins) into
// Sites and system sites: preview → parity → dual run → cut-over → (rollback within 7 days).
// New sites may not be applied before the cut-over.

const h = vi.hoisted(() => ({ emit: vi.fn(), mfa: vi.fn() }))

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
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../middleware/require-admin.js', () => ({
  requireSuperAdmin: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden' })
  },
  requireSitesApply: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden' })
  },
  requireRecentMfa: async (request: FastifyRequest, reply: FastifyReply) => {
    h.mfa(request.url)
    if (!request.headers['x-test-mfa']) return reply.status(422).send({ error: 'reauth_required' })
  },
}))

import { sitesRoutes } from '../../sites/routes.js'
import { setKubeSites } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import { compareProbe } from '../../sites/migration/parity.js'
import { dualrunTick, stepCutover } from '../../sites/migration/migration.service.js'
import * as redisClient from '../../services/redis-client.service.js'
import * as rbacRepo from '../../services/redis-rbac.repository.js'

type Store = ReturnType<typeof import('./mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('./mocks.js').InlineRedisMock }).__redis
const W = { 'x-test-write': '1' }
const WM = { 'x-test-write': '1', 'x-test-mfa': '1' }
const cluster = fakeCluster()

const builtIns = buildBuiltInRules({
  domains: { auth: 'auth.dev.stairling.com', app: 'kuma.dev.stairling.com', api: 'jinbe.dev.stairling.com' },
  urls: { loginUi: 'http://auth-kratos-login-ui:3000', kratosPublic: 'http://auth-kratos-public:80', kratosAdmin: 'x', adminUi: 'http://auth-kuma:80', jinbeInternal: 'http://auth-jinbe:8080' },
})
const expenses: OathkeeperRule = {
  id: 'expenses-oathkeeper',
  upstream: { url: 'http://expenses.expenses.svc.cluster.local:8080' },
  match: { url: '<https?>://expenses.dev.stairling.com/<.*>', methods: ['GET', 'POST'] },
  authenticators: [{ handler: 'cookie_session' }],
  authorizer: { handler: 'remote_json', config: { payload: '{"input":{"app":"expenses"}}' } },
  mutators: [{ handler: 'header' }],
}
const stray: OathkeeperRule = {
  id: 'stray-rule-7',
  upstream: { url: 'http://stray:80' },
  match: { url: '<https?>://<[a-z]+>.dev.stairling.com/stray', methods: ['GET'] },
  authenticators: [{ handler: 'noop' }],
  authorizer: { handler: 'allow' },
  mutators: [{ handler: 'noop' }],
}

/** gatekit /match with Oathkeeper's regexp semantics (fixtures.oathkeeperRegex). */
async function gatekitFetch(url: URL | string, init: { body: string }) {
  const path = new URL(url.toString()).pathname
  const body = JSON.parse(init.body)
  let answer: unknown = {}
  if (path === '/match') {
    const matched = (body.rules as OathkeeperRule[])
      .filter((r) => r.match.methods.includes(body.method) && oathkeeperRegex(r.match.url).test(body.url))
      .map((r) => r.id)
    answer = { matched, verdict: matched.length === 0 ? 'none' : matched.length === 1 ? 'one' : 'multiple' }
  } else if (path === '/compile') {
    answer = { results: body.patterns.map((p: { id: string }) => ({ id: p.id, ok: true })) }
  } else if (path === '/overlap') {
    answer = { overlaps: [] }
  }
  return new Response(JSON.stringify(answer), { status: 200, headers: { 'content-type': 'application/json' } })
}

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request) => { request.userContext = { id: 'sam', email: 'sam@x.test', name: 'Sam' } })
  await app.register(sitesRoutes, { prefix: '/sites' })
  await app.ready()
})
afterAll(() => app.close())
afterEach(() => vi.useRealTimers())

beforeEach(() => {
  redis.clear()
  store.reset()
  cluster.reset()
  store.s.accessRules = [...builtIns, expenses, stray]
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_KUBE = 'off'
  process.env.SITES_NAMESPACE = 'auth'
  process.env.SITES_ZONES = '[{"suffix":"dev.stairling.com","wildcardTls":true}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.stairling.com'
  process.env.SITES_APPLY_POLL_MS = '0'
  process.env.SITES_RULES_LOADED_TIMEOUT_MS = '5000'
  process.env.SITES_MIGRATION_DUALRUN_MIN_SEC = '0'
  resetSitesConfig()
  setKubeSites(cluster.kube)
  vi.stubGlobal('fetch', gatekitFetch)
})

const FIXES = { fixes: { kuma: ['pin-app'], jinbe: ['pin-app'] }, decisions: { 'stray-rule-7': 'drop' } }
const preview = (body: object = FIXES) => app.inject({ method: 'POST', url: '/sites/migration/preview', headers: W, payload: body })
const state = async () => (await app.inject({ method: 'GET', url: '/sites/migration' })).json()

async function toDualRun() {
  expect((await preview()).statusCode).toBe(200)
  const parity = await app.inject({ method: 'POST', url: '/sites/migration/parity', headers: W })
  expect(parity.json().regressions).toEqual([])
  const start = await app.inject({ method: 'POST', url: '/sites/migration/dualrun', headers: W, payload: { action: 'start' } })
  expect(start.statusCode).toBe(200)
  await dualrunTick()
}

async function cutOver() {
  await toDualRun()
  const res = await app.inject({ method: 'POST', url: '/sites/migration/cutover', headers: WM, payload: { note: 'Migration to Sites' } })
  expect(res.statusCode).toBe(202)
  for (const name of cluster.crs.keys()) cluster.operator(name)
  return stepCutover()
}

describe('state', () => {
  it('starts not-started with the legacy rule count', async () => {
    expect(await state()).toMatchObject({ state: 'not-started', legacyRules: builtIns.length + 2 })
  })
})

describe('preview', () => {
  it('groups built-ins into system sites, the rest by host, and lists what it cannot place', async () => {
    const res = await preview({})
    expect(res.statusCode).toBe(200)
    const groups = res.json().groups as Array<{ proposedSite: string; kind: string; legacyRuleIds: string[]; siteCr: { spec: { system?: boolean; gates: unknown[]; hosts: string[] } }; warnings: Array<{ code: string; level: string }>; changes: unknown[] }>
    const by = (n: string) => groups.find((g) => g.proposedSite === n)!
    expect(by('kuma')).toMatchObject({ kind: 'system', legacyRuleIds: ['kuma-api-preflight', 'kuma-api', 'kuma-settings', 'kuma-app'] })
    expect(by('kuma').siteCr.spec.system).toBe(true)
    expect(by('kuma').siteCr.spec.gates).toHaveLength(4)
    expect(by('sign-in')).toMatchObject({ kind: 'system', legacyRuleIds: ['selfservice-root', 'selfservice-ui', 'kratos-public'] })
    expect(by('expenses')).toMatchObject({ kind: 'site', legacyRuleIds: ['expenses-oathkeeper'] })
    expect(by('expenses').siteCr.spec.hosts).toEqual(['expenses.dev.stairling.com'])
    expect(groups.find((g) => g.kind === 'unassigned')!.legacyRuleIds).toEqual(['stray-rule-7'])
    // kuma-api's authorizer does not pin the app: the operator would refuse it until opted into the fix.
    expect(by('kuma').warnings).toContainEqual(expect.objectContaining({ code: 'app_not_pinned', level: 'block' }))
    // `http<(s?)>://` is rewritten to the operator's `<https?>://` — same requests, listed as a change.
    expect(by('sign-in').changes.length).toBeGreaterThan(0)
    expect((await state()).state).toBe('previewed')
  })

  it('opted-in fixes and decisions clear the blocks', async () => {
    const groups = (await preview()).json().groups as Array<{ kind: string; warnings: Array<{ level: string }> }>
    expect(groups.filter((g) => g.kind !== 'unassigned').flatMap((g) => g.warnings).filter((w) => w.level === 'block')).toEqual([])
  })

  it('needs admin:write', async () => {
    expect((await app.inject({ method: 'POST', url: '/sites/migration/preview', payload: {} })).statusCode).toBe(403)
  })
})

describe('parity', () => {
  it('matches every legacy probe against both rule sets: the dropped stray differs, nothing regresses', async () => {
    await preview()
    const report = (await app.inject({ method: 'POST', url: '/sites/migration/parity', headers: W })).json()
    expect(report.total).toBeGreaterThan(20)
    expect(report.regressions).toEqual([])
    expect(report.differs.every((d: { cause: string }) => d.cause === 'decision:stray-rule-7')).toBe(true)
    expect(report.identical + report.differs.length).toBe(report.total)
  })

  it('a difference no opted-in change explains is a regression', () => {
    const mapping = new Map([['site-kuma-kuma-api', 'kuma-api']])
    expect(compareProbe({ method: 'GET', url: 'u' }, { matched: ['kuma-api'], verdict: 'one' }, { matched: ['site-kuma-kuma-api'], verdict: 'one' }, mapping, new Map()).same).toBe(true)
    const diff = compareProbe({ method: 'GET', url: 'u' }, { matched: ['kuma-api'], verdict: 'one' }, { matched: [], verdict: 'none' }, mapping, new Map())
    expect(diff).toMatchObject({ same: false, regression: true })
  })

  it('is refused before a preview', async () => {
    expect((await app.inject({ method: 'POST', url: '/sites/migration/parity', headers: W })).statusCode).toBe(409)
  })
})

describe('dual run', () => {
  it('replays the corpus and becomes eligible after the minimum duration with no regression', async () => {
    await toDualRun()
    const s = (await app.inject({ method: 'GET', url: '/sites/migration/dualrun' })).json()
    expect(s).toMatchObject({ regressions: [], minDurationSec: 0, eligible: true })
    expect(s.compared).toBeGreaterThan(0)
    expect((await state()).state).toBe('dual-run')
    const stop = await app.inject({ method: 'POST', url: '/sites/migration/dualrun', headers: W, payload: { action: 'stop' } })
    expect(stop.statusCode).toBe(200)
    expect((await state()).state).toBe('previewed')
  })

  it('will not start while a block remains', async () => {
    await preview({})
    await app.inject({ method: 'POST', url: '/sites/migration/parity', headers: W })
    const res = await app.inject({ method: 'POST', url: '/sites/migration/dualrun', headers: W, payload: { action: 'start' } })
    expect(res.statusCode).toBe(409)
  })
})

describe('cut-over and rollback', () => {
  const applyNewSite = async () => {
    const site = payrollSite({ groups: { platform: {}, orgGrantable: {} } })
    const put = await app.inject({ method: 'PUT', url: '/sites/payroll', headers: W, payload: { site } })
    return app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: WM, payload: { version: put.json().version } })
  }

  it('no new site is applied before the cut-over', async () => {
    const res = await applyNewSite()
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toBe('migration_pending')
    expect(cluster.crs.size).toBe(0)
  })

  it('needs MFA and an eligible dual run', async () => {
    await preview()
    expect((await app.inject({ method: 'POST', url: '/sites/migration/cutover', headers: W, payload: {} })).statusCode).toBe(422)
    expect((await app.inject({ method: 'POST', url: '/sites/migration/cutover', headers: WM, payload: {} })).statusCode).toBe(409)
  })

  it('creates the Site CRs, waits for RulesLoaded, then opens applies of new sites', async () => {
    const done = await cutOver()
    expect(done.state).toBe('cut-over')
    expect([...cluster.crs.keys()].sort()).toEqual(['expenses', 'jinbe', 'kuma', 'sign-in'])
    expect(cluster.crs.get('kuma')!.spec.system).toBe(true)
    expect(cluster.crs.get('expenses')!.spec.system).toBeUndefined()
    const s = await state()
    expect(s.state).toBe('cut-over')
    expect(new Date(s.rollbackUntil).getTime() - new Date(s.cutoverAt).getTime()).toBe(7 * 86_400_000)
    expect(s.cutover.stages.every((x: { state: string }) => x.state === 'done')).toBe(true)
    expect((await applyNewSite()).statusCode).toBe(200)
  })

  it('removes what it created when the rules do not load in time', async () => {
    await toDualRun()
    vi.useFakeTimers({ toFake: ['Date'] })
    await app.inject({ method: 'POST', url: '/sites/migration/cutover', headers: WM, payload: {} })
    vi.setSystemTime(Date.now() + 6000)
    const out = await stepCutover()
    expect(out.state).toBe('dual-run')
    expect(cluster.crs.size).toBe(0)
    expect((await state()).cutover.state).toBe('failed')
  })

  it('rollback restores the frozen legacy rules and pauses the migrated sites, within the window only', async () => {
    await cutOver()
    store.s.accessRules = []
    const res = await app.inject({ method: 'POST', url: '/sites/migration/rollback', headers: WM })
    expect(res.statusCode).toBe(200)
    expect(store.s.accessRules.map((r) => r.id)).toContain('kuma-api')
    expect(cluster.crs.get('kuma')!.spec.paused).toBe(true)
    expect((await state()).state).toBe('rolled-back')
    expect((await applyNewSite()).statusCode).toBe(409)
  })

  it('rollback after the window is refused', async () => {
    await cutOver()
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(Date.now() + 8 * 86_400_000)
    const res = await app.inject({ method: 'POST', url: '/sites/migration/rollback', headers: WM })
    expect(res.statusCode).toBe(409)
    expect((await state()).state).toBe('done')
  })
})
