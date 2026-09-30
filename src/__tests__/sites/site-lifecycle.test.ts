import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'
import { payrollSite, ACK } from './fixtures.js'
import { fakeGatekit } from './mocks.js'
import { fakeCluster } from './harness.js'

// Wave 19: ephemeral sites (paused by jinbe when their TTL passes, renewable with sites:write) and
// deletion requests (a key may ask; a person with sites:delete, never the requester, never through a
// key, decides). Over HTTP, with the real route-access hook and delegation gate; the user's rights
// come from headers (permission stand-ins), the step-up from x-test-mfa.

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
vi.mock('../../services/org-grants.repository.js', () => ({ orgGrantsRepository: { getAll: vi.fn(async () => ({})) } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../audit/deny.js', () => ({ denyAudit: vi.fn() }))
vi.mock('../../middleware/require-permission.js', async () => (await import('../helpers/permission-stand-ins.js')).permissionStandIn())
vi.mock('../../middleware/require-admin.js', async () => (await import('../helpers/permission-stand-ins.js')).adminStandIn())

import { installRouteAccess } from '../../policy/route-access.js'
import { delegationGate } from '../../middleware/delegation-gate.js'
import { sitesRoutes } from '../../sites/routes.js'
import { setKubeSites } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import { expireDue } from '../../sites/ephemeral.js'
import { sitesTick } from '../../sites/sync.js'
import { approveDeletionRequest } from '../../sites/deletion-requests.js'
import { sitesRepository } from '../../sites/repository.js'
import { CATALOG } from '../../policy/catalog.js'
import * as redisClient from '../../services/redis-client.service.js'
import * as rbacRepo from '../../services/redis-rbac.repository.js'

type Store = ReturnType<typeof import('./mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('./mocks.js').InlineRedisMock }).__redis
const cluster = fakeCluster()

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const who = (request.headers['x-test-user'] as string | undefined) ?? 'sam'
    const scopes = request.headers['x-scopes'] as string | undefined
    request.userContext = {
      id: `${who}-id`, email: `${who}@x.test`, name: who,
      ...(scopes !== undefined
        ? { authVia: 'delegated', delegation: { clientId: 'claude', scopes: scopes.split(' ').filter(Boolean), kind: 'personal', via: 'auth-mcp', keyStepUpAt: new Date(Date.now() - 3600_000).toISOString() } }
        : { authVia: 'session' }),
    } as never
  })
  app.addHook('preHandler', delegationGate)
  await app.register(sitesRoutes, { prefix: '/api/admin/sites' })
  await app.ready()
})
afterAll(() => app.close())
afterEach(() => vi.useRealTimers())

beforeEach(() => {
  redis.clear()
  store.reset()
  cluster.reset()
  h.emit.mockClear()
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_KUBE = 'off'
  process.env.SITES_ZONES = '[{"suffix":"dev.example.com","wildcardTls":true}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.example.com'
  process.env.SITES_APPLY_POLL_MS = '0'
  process.env.SITES_RULES_LOADED_TIMEOUT_MS = '5000'
  delete process.env.SITES_PRODUCTION
  delete process.env.SITES_FOUR_EYES
  resetSitesConfig()
  setKubeSites(cluster.kube)
  vi.stubGlobal('fetch', fakeGatekit(h.gatekit))
})

const ALL = 'sites:read,sites:write,sites:apply,sites:delete'
/** A person in a browser, holding `perms`, with a fresh second factor. */
const person = (who: string, perms = ALL) => ({ 'x-test-user': who, 'x-test-perms': perms, 'x-test-mfa': '1' })
/** `who`'s MCP key with these scopes (the holder holds everything). */
const key = (scopes: string, who = 'sam') => ({ 'x-test-user': who, 'x-test-perms': ALL, 'x-scopes': scopes })

const inject = (method: 'GET' | 'PUT' | 'POST' | 'DELETE', url: string, headers: Record<string, string>, payload?: object) =>
  app.inject({ method, url: `/api/admin/sites${url}`, headers, ...(payload ? { payload } : {}) })

async function save(body: Record<string, unknown> = {}, headers = person('sam')) {
  const cur = await inject('GET', '/payroll', headers)
  const res = await inject('PUT', '/payroll', { ...headers, ...(cur.statusCode === 200 ? { 'if-match': cur.headers.etag as string } : {}) }, { site: payrollSite(), ...body })
  expect(res.statusCode).toBe(200)
  return res.json()
}
async function applyIt(version = 1) {
  const res = await inject('POST', '/payroll/apply', person('sam'), { version, acknowledge: ACK })
  expect(res.statusCode).toBe(200)
}
const verbs = () => h.emit.mock.calls.map(([e]) => (e as { verb: string }).verb)
const settle = () => new Promise((r) => setTimeout(r, 0))

describe('ephemeral sites', () => {
  it('saves with a TTL and lists the expiry; 24 hours by default; bounded 1 hour to 7 days', async () => {
    const t0 = Date.now()
    const saved = await save({ ephemeral: { ttl: '2h' } })
    expect(saved.ephemeral).toMatchObject({ ttlSec: 7200, expired: false })
    expect(Date.parse(saved.ephemeral.expiresAt) - t0).toBeGreaterThanOrEqual(7200_000 - 1000)
    const list = (await inject('GET', '', person('sam'))).json()
    expect(list[0]).toMatchObject({ name: 'payroll', ephemeral: { ttlSec: 7200, expired: false } })
    expect((await inject('GET', '/payroll', person('sam'))).json().ephemeral).toMatchObject({ ttlSec: 7200 })

    expect((await save({ ephemeral: {} })).ephemeral.ttlSec).toBe(86_400)
    expect((await save({ ephemeral: { ttl: 3600 } })).ephemeral.ttlSec).toBe(3600)
    const cur = await inject('GET', '/payroll', person('sam'))
    for (const ttl of ['30m', '8d', 60, 'soon']) {
      const res = await inject('PUT', '/payroll', { ...person('sam'), 'if-match': cur.headers.etag as string }, { site: payrollSite(), ephemeral: { ttl } })
      expect(res.statusCode).toBe(400)
    }
    const platform = (await inject('GET', '/platform', person('sam'))).json()
    expect(platform.ephemeral).toEqual({ minSec: 3600, maxSec: 604_800, defaultSec: 86_400 })
  })

  it('a save without `ephemeral` keeps the expiry; null makes the site permanent', async () => {
    const first = await save({ ephemeral: { ttl: '3h' } })
    const again = await save()
    expect(again.ephemeral).toBeUndefined()
    expect((await inject('GET', '/payroll', person('sam'))).json().ephemeral.expiresAt).toBe(first.ephemeral.expiresAt)
    expect((await save({ ephemeral: null })).ephemeral).toBeNull()
    expect((await inject('GET', '', person('sam'))).json()[0].ephemeral).toBeNull()
    await settle()
    expect(verbs()).toEqual(expect.arrayContaining(['ephemeral', 'ephemeral_off']))
  })

  it('when the TTL passes (fake clock), the site is paused — nothing deleted — audited, marked expired; once', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    const t0 = new Date('2026-10-01T10:00:00Z')
    vi.setSystemTime(t0)
    await save({ ephemeral: { ttl: '2h' } })
    await applyIt()
    expect(cluster.crs.get('payroll')!.spec.paused).toBe(false)

    vi.setSystemTime(new Date(t0.getTime() + 3600_000))
    expect(await expireDue()).toEqual({ expired: [], errors: [] })

    vi.setSystemTime(new Date(t0.getTime() + 2 * 3600_000 + 1000))
    h.emit.mockClear()
    expect(await expireDue()).toEqual({ expired: ['payroll'], errors: [] })
    expect(cluster.crs.get('payroll')!.spec.paused).toBe(true)
    expect(cluster.kube.deleted).toEqual([])
    expect((await sitesRepository.get('payroll'))!.site.state).toBe('paused')
    await settle()
    expect(verbs()).toEqual(expect.arrayContaining(['pause', 'expire']))
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ verb: 'expire', actor: expect.objectContaining({ email: 'jinbe (ephemeral)' }) }))
    const listed = (await inject('GET', '', person('sam'))).json()[0]
    expect(listed).toMatchObject({ status: 'paused', ephemeral: { expired: true, remainingSec: 0, expiredAt: expect.any(String) } })

    // Idempotent: a second sweep (another replica, a restart) pauses nothing again.
    const writes = cluster.kube.applied.length
    expect(await expireDue()).toEqual({ expired: [], errors: [] })
    expect(cluster.kube.applied.length).toBe(writes)
  })

  it('expires a site never applied (no Kubernetes needed), and runs from the background tick', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    await save({ ephemeral: { ttl: '1h' } })
    vi.setSystemTime(new Date(Date.now() + 3601_000))
    await sitesTick()
    expect((await sitesRepository.get('payroll'))!.site.state).toBe('paused')
    expect(cluster.kube.applied).toEqual([])
    expect((await inject('GET', '/payroll', person('sam'))).json().ephemeral.expired).toBe(true)
  })

  it('a site already paused when its TTL passes is only marked expired', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    await save({ ephemeral: { ttl: '1h' } })
    await applyIt()
    expect((await inject('POST', '/payroll/pause', person('sam'))).statusCode).toBe(200)
    const writes = cluster.kube.applied.length
    vi.setSystemTime(new Date(Date.now() + 3601_000))
    expect((await expireDue()).expired).toEqual(['payroll'])
    expect(cluster.kube.applied.length).toBe(writes)
  })

  it('renewal (sites:write, a key included) moves the expiry; an expired site stays paused', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    await save({ ephemeral: { ttl: '1h' } })
    vi.setSystemTime(new Date(Date.now() + 1800_000))
    const renewed = await inject('POST', '/payroll/ttl', key('sites:read sites:write'), { ttl: '1d' })
    expect(renewed.statusCode).toBe(200)
    expect(renewed.json()).toMatchObject({ name: 'payroll', state: 'active', ephemeral: { ttlSec: 86_400, expired: false } })
    vi.setSystemTime(new Date(Date.now() + 3600_000))
    expect((await expireDue()).expired).toEqual([])

    vi.setSystemTime(new Date(Date.now() + 86_400_000))
    expect((await expireDue()).expired).toEqual(['payroll'])
    const again = await inject('POST', '/payroll/ttl', person('sam'), {})
    expect(again.json()).toMatchObject({ state: 'paused', ephemeral: { ttlSec: 86_400, expired: false }, hint: expect.stringContaining('resume') })
    await settle()
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ verb: 'ttl_renew', details: expect.objectContaining({ wasExpired: true }) }))
  })

  it('renewal: 409 on a permanent site, 403 for a key without sites:write, bounded like a save', async () => {
    await save()
    expect((await inject('POST', '/payroll/ttl', person('sam'), {})).json().error).toBe('not_ephemeral')
    await save({ ephemeral: {} })
    const denied = await inject('POST', '/payroll/ttl', key('sites:read'), {})
    expect(denied.statusCode).toBe(403)
    expect(denied.json().reason).toBe('scope_missing:sites:write')
    expect((await inject('POST', '/payroll/ttl', person('sam'), { ttl: '10d' })).statusCode).toBe(400)
  })

  it('a deleted site forgets its expiry: restored, it is permanent', async () => {
    await save({ ephemeral: {} })
    expect((await inject('DELETE', '/payroll', person('sam'))).statusCode).toBe(200)
    expect((await inject('POST', '/payroll/restore', person('sam'))).statusCode).toBe(200)
    expect((await inject('GET', '/payroll', person('sam'))).json().ephemeral).toBeNull()
  })
})

describe('deletion requests', () => {
  async function requested(headers: Record<string, string> = key('sites:read sites:write')) {
    const res = await inject('POST', '/payroll/deletion-requests', headers, { reason: 'demo over' })
    expect(res.statusCode).toBe(201)
    return res.json()
  }

  it('a key may request; the request is pending, one at a time, and listed for the inbox', async () => {
    await save()
    const req = await requested()
    expect(req).toMatchObject({ site: 'payroll', state: 'pending', requestedBy: 'sam@x.test', requesterId: 'sam-id', requestedVia: 'claude', reason: 'demo over' })
    expect((await inject('POST', '/payroll/deletion-requests', person('kim'), {})).json().error).toBe('deletion_request_pending')
    const list = (await inject('GET', '/deletion-requests?state=pending', person('kim'))).json()
    expect(list).toHaveLength(1)
    const inboxSam = (await inject('GET', '/deletion-requests/pending', person('sam'))).json()
    expect(inboxSam[0]).toMatchObject({ id: req.id, requestedByYou: true })
    const inboxKim = (await inject('GET', '/deletion-requests/pending', person('kim'))).json()
    expect(inboxKim[0].requestedByYou).toBe(false)
    expect((await inject('POST', '/nothing/deletion-requests', person('sam'), {})).statusCode).toBe(404)
    await settle()
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ verb: 'deletion_request', actor: expect.objectContaining({ act: expect.objectContaining({ client_id: 'claude' }) }) }))
  })

  it('another person with sites:delete approves: the existing delete path runs, as the approver', async () => {
    await save()
    await applyIt()
    const req = await requested()
    h.emit.mockClear()
    const ok = await inject('POST', `/deletion-requests/${req.id}/approve`, person('kim'))
    expect(ok.statusCode).toBe(200)
    expect(ok.json()).toMatchObject({ name: 'payroll', deleted: true, request: { state: 'approved', decidedBy: 'kim@x.test' } })
    expect(cluster.kube.deleted).toEqual(['payroll'])
    expect(await sitesRepository.get('payroll')).toBeNull()
    expect((await inject('GET', '/deleted', person('kim'))).json()[0]).toMatchObject({ name: 'payroll', deletedBy: 'kim@x.test' })
    await settle()
    expect(verbs()).toEqual(expect.arrayContaining(['delete', 'deletion_approve']))
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ verb: 'delete', details: expect.objectContaining({ deletionRequest: req.id }) }))
    expect((await inject('POST', `/deletion-requests/${req.id}/approve`, person('lee'))).json().error).toBe('request_decided')
  })

  it('four-eyes: the requester cannot approve their own request, whoever they are', async () => {
    await save()
    const req = await requested(person('sam'))
    const self = await inject('POST', `/deletion-requests/${req.id}/approve`, person('sam'))
    expect(self.statusCode).toBe(403)
    expect(self.json().error).toBe('second_approver_required')
    // Requested through a key, approved by its holder in the browser: still the same person.
    await inject('POST', `/deletion-requests/${req.id}/reject`, person('kim'))
    const viaKey = await requested()
    expect((await inject('POST', `/deletion-requests/${viaKey.id}/approve`, person('sam'))).json().error).toBe('second_approver_required')
    expect(await sitesRepository.get('payroll')).not.toBeNull()
  })

  it('never approved or rejected through a key, whatever its scopes: the gate refuses sites:delete', async () => {
    await save()
    const req = await requested(person('sam'))
    for (const verb of ['approve', 'reject']) {
      const res = await inject('POST', `/deletion-requests/${req.id}/${verb}`, key('sites:read sites:write sites:delete', 'kim'))
      expect(res.statusCode).toBe(403)
      expect(res.json().reason).toBe('delegation_ineligible:sites:delete')
    }
    expect(await sitesRepository.get('payroll')).not.toBeNull()
    // And the service refuses a delegated actor on its own, should a route ever reach it.
    await expect(approveDeletionRequest(req.id, { id: 'kim-id', email: 'kim@x.test', act: { client_id: 'claude', via: 'auth-mcp', kind: 'personal' } } as never))
      .rejects.toMatchObject({ statusCode: 403, code: 'delegation_refused' })
    expect(CATALOG['sites:delete']).toMatchObject({ delegable: 'never', stepUp: true })
  })

  it('deciding needs sites:delete and a fresh second factor', async () => {
    await save()
    const req = await requested()
    expect((await inject('POST', `/deletion-requests/${req.id}/approve`, person('kim', 'sites:read,sites:write,sites:apply'))).statusCode).toBe(403)
    const { 'x-test-mfa': _mfa, ...noMfa } = person('kim')
    expect((await inject('POST', `/deletion-requests/${req.id}/approve`, noMfa)).statusCode).toBe(422)
    expect(await sitesRepository.get('payroll')).not.toBeNull()
  })

  it('reject closes the request with a reason and deletes nothing', async () => {
    await save()
    const req = await requested()
    const rej = await inject('POST', `/deletion-requests/${req.id}/reject`, person('kim'), { reason: 'still used' })
    expect(rej.json()).toMatchObject({ state: 'rejected', decidedBy: 'kim@x.test', decisionReason: 'still used' })
    expect(await sitesRepository.get('payroll')).not.toBeNull()
    expect((await inject('POST', `/deletion-requests/${req.id}/approve`, person('kim'))).statusCode).toBe(409)
    await settle()
    expect(verbs()).toContain('deletion_reject')
    // A new request may be made once the last one is decided.
    expect((await inject('POST', '/payroll/deletion-requests', person('sam'), {})).statusCode).toBe(201)
  })

  it('a direct delete cancels the pending request', async () => {
    await save()
    const req = await requested()
    expect((await inject('DELETE', '/payroll', person('kim'))).statusCode).toBe(200)
    const [closed] = (await inject('GET', '/deletion-requests', person('kim'))).json()
    expect(closed).toMatchObject({ id: req.id, state: 'cancelled', decisionReason: 'site deleted' })
    expect((await inject('POST', `/deletion-requests/${req.id}/approve`, person('kim'))).json().error).toBe('request_decided')
  })
})
