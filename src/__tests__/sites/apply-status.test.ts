import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { payrollSite } from './fixtures.js'
import { fakeGatekit } from './mocks.js'
import { fakeCluster } from './harness.js'

// S-3: the apply timeline follows the Site CR's conditions (Saved → Permissions published → Site
// accepted → Rules synced → Rules loaded → Ingress/Cert (vanity only) → Verified), rolls back when
// the rules are not loaded in time; status and drift compare the CR with the last applied render.

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
import { stepApply } from '../../sites/applies.js'
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
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_KUBE = 'off'
  process.env.SITES_ZONES = '[{"suffix":"dev.stairling.com","wildcardTls":true}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.stairling.com'
  process.env.SITES_APPLY_POLL_MS = '0'
  process.env.SITES_RULES_LOADED_TIMEOUT_MS = '5000'
  resetSitesConfig()
  setKubeSites(cluster.kube)
  vi.stubGlobal('fetch', fakeGatekit(h.gatekit))
})

async function saveAndApply(site: Site = payrollSite()) {
  const cur = await app.inject({ method: 'GET', url: `/sites/${site.name}` })
  const headers = cur.statusCode === 200 ? { ...W, 'if-match': cur.headers.etag as string } : W
  const put = await app.inject({ method: 'PUT', url: `/sites/${site.name}`, headers, payload: { site } })
  expect(put.statusCode).toBe(200)
  const res = await app.inject({ method: 'POST', url: `/sites/${site.name}/apply`, headers: W, payload: { version: put.json().version } })
  expect(res.statusCode).toBe(200)
  return res.json() as { applyId: string; version: number }
}
const getApply = async (id: string) => (await app.inject({ method: 'GET', url: `/sites/payroll/applies/${id}` })).json()
const stage = (a: { stages: Array<{ id: string; state: string }> }, id: string) => a.stages.find((s) => s.id === id)!

describe('apply timeline', () => {
  it('records Saved and Permissions published, skips Ingress/Cert for a zone site, then waits on the operator', async () => {
    const { applyId } = await saveAndApply()
    const a = await getApply(applyId)
    expect(a.stages.map((s: { id: string }) => s.id)).toEqual(['saved', 'permissions', 'accepted', 'rules-synced', 'rules-loaded', 'ingress', 'certificate', 'verified'])
    expect(stage(a, 'saved').state).toBe('done')
    expect(stage(a, 'permissions').state).toBe('done')
    expect(stage(a, 'permissions').endedAt).toBeTruthy()
    expect(stage(a, 'accepted').state).toBe('running')
    expect(stage(a, 'ingress').state).toBe('skipped')
    expect(stage(a, 'certificate').state).toBe('skipped')
    expect(a).toMatchObject({ state: 'running', version: 1, site: 'payroll' })
  })

  it('follows the conditions to Verified', async () => {
    const { applyId } = await saveAndApply()
    cluster.operator('payroll', { RulesLoaded: 'Loading', Ready: 'NotReady' })
    let a = await stepApply('payroll', applyId)
    expect(stage(a, 'accepted').state).toBe('done')
    expect(stage(a, 'rules-synced').state).toBe('done')
    expect(stage(a, 'rules-loaded').state).toBe('running')
    cluster.operator('payroll')
    a = await stepApply('payroll', applyId)
    expect(a.state).toBe('succeeded')
    expect(a.stages.every((s) => s.state === 'done' || s.state === 'skipped')).toBe(true)
  })

  it('ignores conditions of an older generation', async () => {
    const { applyId } = await saveAndApply()
    cluster.operator('payroll', {}, 0)
    const a = await stepApply('payroll', applyId)
    expect(stage(a, 'accepted').state).toBe('running')
  })

  it('stops at Site accepted when the operator refuses the spec', async () => {
    const { applyId } = await saveAndApply()
    cluster.operator('payroll', { Validated: 'RuleOverlap' })
    const a = await stepApply('payroll', applyId)
    expect(a).toMatchObject({ state: 'failed', code: 'site_invalid' })
    expect(stage(a, 'accepted')).toMatchObject({ state: 'failed', detail: expect.stringContaining('RuleOverlap') })
  })

  it('rolls back to the previous version when the rules are not loaded in time', async () => {
    const first = await saveAndApply()
    cluster.operator('payroll')
    await stepApply('payroll', first.applyId)
    vi.useFakeTimers({ toFake: ['Date'] })
    const second = await saveAndApply(payrollSite({ displayName: 'Payroll 2', upstream: { service: 'payroll', namespace: 'payroll', port: 9090 } }))
    cluster.operator('payroll', { RulesLoaded: 'PodsBehind' })
    expect((await stepApply('payroll', second.applyId)).state).toBe('running')
    vi.setSystemTime(Date.now() + 6000)
    const a = await stepApply('payroll', second.applyId)
    expect(a).toMatchObject({ state: 'rolled-back', code: 'rules_not_loaded' })
    expect(stage(a, 'rules-loaded').state).toBe('failed')
    const last = cluster.kube.applied.at(-1)!
    expect(last.metadata.annotations['auth.w6d.io/version']).toBe('1')
    expect(last.spec.upstream.port).toBe(8080)
    expect((await sitesRepository.get('payroll'))!.applied!.version).toBe(1)
  })

  it('a first apply that never loads removes the Site CR and its permissions', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    const { applyId } = await saveAndApply()
    vi.setSystemTime(Date.now() + 6000)
    const a = await stepApply('payroll', applyId)
    expect(a.state).toBe('rolled-back')
    expect(cluster.kube.deleted).toEqual(['payroll'])
    expect(store.s.routeMaps.payroll).toBeUndefined()
    expect((await sitesRepository.get('payroll'))!.applied).toBeUndefined()
  })

  it('streams the stages as server-sent events and ends on a terminal state', async () => {
    const { applyId } = await saveAndApply()
    cluster.operator('payroll')
    await stepApply('payroll', applyId)
    const res = await app.inject({ method: 'GET', url: `/sites/payroll/applies/${applyId}/events` })
    expect(res.headers['content-type']).toMatch(/^text\/event-stream/)
    expect(res.body).toContain('event: apply')
    expect(res.body).toContain('"state":"succeeded"')
    expect(res.body).toContain('event: done')
  })

  it('404 for an unknown apply', async () => {
    await saveAndApply()
    expect((await app.inject({ method: 'GET', url: '/sites/payroll/applies/nope' })).statusCode).toBe(404)
  })
})

describe('status', () => {
  it('reports generation, conditions and children of the Site CR', async () => {
    await saveAndApply()
    cluster.operator('payroll', { Ready: 'Waiting' })
    const s = (await app.inject({ method: 'GET', url: '/sites/payroll/status' })).json()
    expect(s).toMatchObject({ exists: true, generation: 1, observedGeneration: 1 })
    expect(s.conditions.find((c: { type: string }) => c.type === 'Ready')).toMatchObject({ status: 'False', reason: 'Waiting' })
    expect(s.children).toEqual([{ kind: 'Rule', name: 'payroll-web-abc', specHash: 'h1', expectedHash: null, conditions: [], loadedOn: null }])
  })

  it('says so when the Site CR does not exist', async () => {
    await app.inject({ method: 'PUT', url: '/sites/payroll', headers: W, payload: { site: payrollSite() } })
    expect((await app.inject({ method: 'GET', url: '/sites/payroll/status' })).json()).toMatchObject({ exists: false, conditions: [], children: [] })
  })
})

describe('drift', () => {
  it('nothing differs right after an apply', async () => {
    await saveAndApply()
    cluster.operator('payroll')
    expect((await app.inject({ method: 'GET', url: '/sites/payroll/drift' })).json()).toMatchObject({ items: [], appliedVersion: 1 })
  })

  it('lists kubectl edits, permission edits, a missing CR and unloaded rules', async () => {
    await saveAndApply()
    cluster.operator('payroll', { RulesLoaded: 'PodsBehind' })
    cluster.crs.get('payroll')!.spec.gates[0].match.methods.push('TRACE')
    store.s.routeMaps.payroll = { rules: [{ method: 'GET', path: '/x' }] }
    const items = (await app.inject({ method: 'GET', url: '/sites/payroll/drift' })).json().items as Array<{ artefact: string; field: string }>
    expect(items).toEqual(expect.arrayContaining([
      expect.objectContaining({ artefact: 'Site/payroll', field: expect.stringMatching(/^spec\.gates\[.+\]\.match\.methods/) }),
      expect.objectContaining({ artefact: 'route_map/payroll' }),
      expect.objectContaining({ artefact: 'Site/payroll', field: 'status.conditions.RulesLoaded' }),
    ]))
    cluster.crs.delete('payroll')
    const gone = (await app.inject({ method: 'GET', url: '/sites/payroll/drift' })).json().items
    expect(gone).toContainEqual(expect.objectContaining({ artefact: 'Site/payroll', field: '*', actual: 'missing' }))
  })

  it('accept folds what the intent can hold into a draft and names what it cannot', async () => {
    await saveAndApply()
    cluster.operator('payroll')
    cluster.crs.get('payroll')!.spec.upstream.port = 9999
    cluster.crs.get('payroll')!.spec.gates[0].match.methods.push('TRACE')
    store.s.roles.payroll = { admin: ['*'], viewer: ['payslips:read'] }
    const res = await app.inject({ method: 'POST', url: '/sites/payroll/drift/accept', headers: W })
    expect(res.statusCode).toBe(200)
    const out = res.json()
    expect(out.draft.site.upstream.port).toBe(9999)
    expect(out.draft.site.roles).toEqual({ admin: ['*'], viewer: ['payslips:read'] })
    expect(out.draft.baseVersion).toBe(1)
    expect(out.folded).toEqual(expect.arrayContaining(['upstream', 'roles']))
    expect(out.notFolded.some((f: string) => f.startsWith('spec.gates'))).toBe(true)
    expect((await app.inject({ method: 'POST', url: '/sites/payroll/drift/accept' })).statusCode).toBe(403)
  })
})
