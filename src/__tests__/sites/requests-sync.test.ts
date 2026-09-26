import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { payrollSite } from './fixtures.js'
import { fakeGatekit } from './mocks.js'
import { fakeCluster } from './harness.js'

// S-3: apply requests with the optional four-eyes rule, and the sync loop that re-creates missing
// or drifted Site CRs from the intent in Redis (the source of truth), a few per tick.

const h = vi.hoisted(() => ({
  gatekit: {
    compile: (patterns: Array<{ id: string }>) => ({ results: patterns.map((p) => ({ id: p.id, ok: true })) }) as unknown,
    overlap: (_b: unknown) => ({ overlaps: [] }) as unknown,
    status: 200,
    calls: [] as Array<{ path: string; body: Record<string, unknown> }>,
  },
  emit: vi.fn(),
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
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../middleware/require-admin.js', () => ({
  requireSuperAdmin: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden' })
  },
  requireSitesApply: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden' })
  },
  requireRecentMfa: async () => {},
}))

import { sitesRoutes } from '../../sites/routes.js'
import { setKubeSites } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import { syncOnce, resetSyncCooldown } from '../../sites/sync.js'
import { startApply } from '../../sites/applies.js'
import { sitesRepository } from '../../sites/repository.js'
import * as redisClient from '../../services/redis-client.service.js'
import * as rbacRepo from '../../services/redis-rbac.repository.js'
import type { Site } from '../../sites/schemas.js'

type Store = ReturnType<typeof import('./mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('./mocks.js').InlineRedisMock }).__redis
const W = { 'x-test-write': '1' }
const cluster = fakeCluster()

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request) => {
    const who = (request.headers['x-test-user'] as string | undefined) ?? 'sam'
    request.userContext = { id: who, email: `${who}@x.test`, name: who }
  })
  await app.register(sitesRoutes, { prefix: '/sites' })
  await app.ready()
})
afterAll(() => app.close())
afterEach(() => vi.useRealTimers())

beforeEach(() => {
  redis.clear()
  store.reset()
  cluster.reset()
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_KUBE = 'off'
  process.env.SITES_ZONES = '[{"suffix":"dev.stairling.com","wildcardTls":true}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.stairling.com'
  process.env.SITES_APPLY_POLL_MS = '0'
  process.env.SITES_RULES_LOADED_TIMEOUT_MS = '5000'
  delete process.env.SITES_FOUR_EYES
  resetSitesConfig()
  resetSyncCooldown()
  setKubeSites(cluster.kube)
  vi.stubGlobal('fetch', fakeGatekit(h.gatekit))
})

const put = async (site: Site = payrollSite()) => {
  const cur = await app.inject({ method: 'GET', url: `/sites/${site.name}` })
  const headers = cur.statusCode === 200 ? { ...W, 'if-match': cur.headers.etag as string } : W
  const res = await app.inject({ method: 'PUT', url: `/sites/${site.name}`, headers, payload: { site } })
  expect(res.statusCode).toBe(200)
  return res.json().version as number
}
const request = (version: number, who = 'sam') =>
  app.inject({ method: 'POST', url: '/sites/payroll/requests', headers: { ...W, 'x-test-user': who }, payload: { version, note: 'please' } })
const decide = (id: string, verb: 'approve' | 'reject', who: string, payload: object = {}) =>
  app.inject({ method: 'POST', url: `/sites/requests/${id}/${verb}`, headers: { ...W, 'x-test-user': who }, payload })

describe('apply requests and four-eyes', () => {
  it('four-eyes off (default): apply goes straight through; a request can be approved by anyone, who applies it', async () => {
    const v = await put()
    const req = await request(v)
    expect(req.statusCode).toBe(201)
    expect(req.json()).toMatchObject({ site: 'payroll', version: v, state: 'pending', requestedBy: 'sam@x.test', needsSecondApprover: false })
    const list = (await app.inject({ method: 'GET', url: '/sites/requests?state=pending' })).json()
    expect(list).toHaveLength(1)
    const ok = await decide(req.json().id, 'approve', 'sam')
    expect(ok.statusCode).toBe(200)
    expect(ok.json()).toMatchObject({ state: 'applied', decidedBy: 'sam@x.test', applyId: expect.any(String) })
    expect(cluster.crs.has('payroll')).toBe(true)
  })

  it('four-eyes high-risk: a high-risk apply needs an approved request from another super admin', async () => {
    process.env.SITES_FOUR_EYES = 'high-risk'
    resetSitesConfig()
    const v = await put() // a new site whose platform group gets "*": high risk
    const direct = await app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: W, payload: { version: v } })
    expect(direct.statusCode).toBe(409)
    expect(direct.json().error).toBe('approval_required')
    expect(cluster.crs.has('payroll')).toBe(false)
    const req = (await request(v)).json()
    expect(req.needsSecondApprover).toBe(true)
    const self = await decide(req.id, 'approve', 'sam')
    expect(self.statusCode).toBe(403)
    expect(self.json().error).toBe('second_approver_required')
    const other = await decide(req.id, 'approve', 'kim')
    expect(other.json()).toMatchObject({ state: 'applied', decidedBy: 'kim@x.test' })
  })

  it('four-eyes high-risk lets a low-risk apply through', async () => {
    process.env.SITES_FOUR_EYES = 'high-risk'
    resetSitesConfig()
    const site = payrollSite({ groups: { platform: {}, orgGrantable: {} } })
    site.routes.items = site.routes.items.filter((r) => r.access.kind !== 'public') // a new public route is high risk
    const v = await put(site)
    expect((await app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: W, payload: { version: v } })).statusCode).toBe(200)
  })

  it('reject closes the request with a reason; a decided or stale request cannot be approved', async () => {
    const v = await put()
    const req = (await request(v)).json()
    const rej = await decide(req.id, 'reject', 'kim', { reason: 'not now' })
    expect(rej.json()).toMatchObject({ state: 'rejected', reason: 'not now' })
    expect((await decide(req.id, 'approve', 'kim')).statusCode).toBe(409)
    const req2 = (await request(v)).json()
    await put(payrollSite({ displayName: 'Changed' }))
    const stale = await decide(req2.id, 'approve', 'kim')
    expect(stale.statusCode).toBe(409)
    expect(stale.json().error).toBe('stale_request')
  })

  it('requesting a version that is not the saved one is refused', async () => {
    const v = await put()
    expect((await request(v + 1)).statusCode).toBe(409)
  })
})

describe('sync loop', () => {
  async function applied(name = 'payroll', host = 'payroll.dev.stairling.com') {
    const site = payrollSite({ name, address: { host }, groups: { platform: {}, orgGrantable: {} } })
    const v = await put(site)
    const res = await app.inject({ method: 'POST', url: `/sites/${name}/apply`, headers: W, payload: { version: v } })
    expect(res.statusCode).toBe(200)
    cluster.operator(name)
    await import('../../sites/applies.js').then((m) => m.stepApply(name, res.json().applyId))
  }

  it('leaves an in-sync Site CR alone', async () => {
    await applied()
    const before = cluster.kube.applied.length
    expect(await syncOnce()).toMatchObject({ recreated: [], rewritten: [] })
    expect(cluster.kube.applied.length).toBe(before)
  })

  it('re-creates a missing Site CR and rewrites a drifted one from the intent', async () => {
    await applied()
    await applied('ledger', 'ledger.dev.stairling.com')
    cluster.crs.delete('payroll')
    cluster.crs.get('ledger')!.spec.upstream.port = 1
    const out = await syncOnce()
    expect(out.recreated).toEqual(['payroll'])
    expect(out.rewritten).toEqual(['ledger'])
    expect(cluster.crs.get('payroll')!.metadata.annotations['auth.w6d.io/version']).toBe('1')
    expect(cluster.crs.get('ledger')!.spec.upstream.port).toBe(8080)
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ verb: 'sync', targetId: 'payroll' }))
  })

  it('is rate limited: at most SITES_SYNC_MAX_PER_TICK per tick, and a site not twice within the cooldown', async () => {
    process.env.SITES_SYNC_MAX_PER_TICK = '1'
    resetSitesConfig()
    await applied()
    await applied('ledger', 'ledger.dev.stairling.com')
    cluster.crs.delete('payroll')
    cluster.crs.delete('ledger')
    expect((await syncOnce()).recreated).toHaveLength(1)
    expect((await syncOnce()).recreated).toHaveLength(1)
    cluster.crs.delete('payroll')
    cluster.crs.delete('ledger')
    const third = await syncOnce()
    expect(third.recreated).toEqual([])
    expect(third.deferred.sort()).toEqual(['ledger', 'payroll'])
    delete process.env.SITES_SYNC_MAX_PER_TICK
  })

  it('does not touch a site while an apply is running', async () => {
    await applied()
    const record = (await sitesRepository.get('payroll'))!
    await startApply(record, 'sam@x.test', null)
    cluster.crs.delete('payroll')
    expect((await syncOnce()).recreated).toEqual([])
  })
})
