import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { payrollSite } from './fixtures.js'
import { fakeGatekit } from './mocks.js'
import { fakeCluster } from './harness.js'

// Owner decision: `admin:write` drafts, saves and requests; `sites:apply` (held only through the
// global "*", i.e. super_admin) + recent MFA applies, rolls back, pauses, deletes, restores, accepts
// drift, approves requests and cuts the migration over. Plus the list's draft-only sites, /platform,
// /deleted and restore.

const h = vi.hoisted(() => ({
  gatekit: {
    compile: (patterns: Array<{ id: string }>) => ({ results: patterns.map((p) => ({ id: p.id, ok: true })) }) as unknown,
    overlap: (_b: unknown) => ({ overlaps: [] }) as unknown,
    status: 200,
    calls: [] as Array<{ path: string; body: Record<string, unknown> }>,
  },
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
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn() } }))
// x-test-perms: the caller's permissions, comma-separated; x-test-mfa: a fresh second factor.
vi.mock('../../middleware/require-admin.js', async () => {
  const { enforcing } = await import('../../policy/declared-routes.js')
  const holds = (request: FastifyRequest, p: string) => String(request.headers['x-test-perms'] ?? '').split(',').includes(p)
  return {
    requireSuperAdmin: enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
      if (!holds(request, 'admin:write')) return reply.status(403).send({ error: 'Forbidden' })
    }, 'admin:write'),
    requireSitesApply: enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
      if (!holds(request, '*')) return reply.status(403).send({ error: 'Forbidden', message: 'needs sites:apply' })
    }, 'sites:apply'),
    requireRecentMfa: async (request: FastifyRequest, reply: FastifyReply) => {
      if (!request.headers['x-test-mfa']) return reply.status(422).send({ error: 'reauth_required' })
    },
  }
})

import { sitesRoutes } from '../../sites/routes.js'
import { setKubeSites } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import { declaredRoutes, enforcing, guardAll, resetDeclaredRoutes } from '../../policy/declared-routes.js'
import * as redisClient from '../../services/redis-client.service.js'
import * as rbacRepo from '../../services/redis-rbac.repository.js'

type Store = ReturnType<typeof import('./mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('./mocks.js').InlineRedisMock }).__redis
const ADMIN = { 'x-test-perms': 'admin:read,admin:write' }
const SUPER = { 'x-test-perms': 'admin:read,admin:write,*', 'x-test-mfa': '1' }
const cluster = fakeCluster()

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request) => { request.userContext = { id: 'sam', email: 'sam@x.test', name: 'Sam' } })
  await app.register(sitesRoutes, { prefix: '/sites' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  redis.clear()
  store.reset()
  cluster.reset()
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_KUBE = 'off'
  process.env.SITES_ZONES = '[{"suffix":"dev.stairling.com","wildcardTls":true}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.stairling.com'
  process.env.SITES_APPLY_POLL_MS = '0'
  delete process.env.SITES_PRODUCTION
  resetSitesConfig()
  setKubeSites(cluster.kube)
  vi.stubGlobal('fetch', fakeGatekit(h.gatekit))
})

const site = () => payrollSite({ groups: { platform: {}, orgGrantable: {} } })
async function saveAs(headers: Record<string, string>) {
  const res = await app.inject({ method: 'PUT', url: '/sites/payroll', headers, payload: { site: site() } })
  expect(res.statusCode).toBe(200)
  return res.json().version as number
}

describe('permissions: admin:write edits and asks, sites:apply applies', () => {
  it('the route table says sites:apply for everything that changes the gateway', async () => {
    resetDeclaredRoutes()
    const admin = Fastify()
    await admin.register(async (scope) => {
      guardAll(scope, enforcing(async () => {}, 'admin:read'), () => false)
      await scope.register(sitesRoutes, { prefix: '/sites' })
    }, { prefix: '/api/admin' })
    await admin.ready()
    const perm = (method: string, path: string) => declaredRoutes().find((r) => r.method === method && r.path === `/api/admin/sites${path}`)?.permission
    for (const [m, p] of [
      ['POST', '/:name/apply'], ['POST', '/:name/rollback'], ['POST', '/:name/pause'], ['POST', '/:name/resume'], ['DELETE', '/:name'],
      ['POST', '/:name/restore'], ['POST', '/:name/drift/accept'], ['POST', '/requests/:id/approve'], ['POST', '/requests/:id/reject'],
      ['POST', '/migration/cutover'], ['POST', '/migration/rollback'],
    ]) expect(`${m} ${p} ${perm(m, p)}`).toBe(`${m} ${p} sites:apply`)
    for (const [m, p] of [['PUT', '/:name'], ['PUT', '/:name/draft'], ['POST', '/:name/requests'], ['PUT', '/:name/logo'], ['POST', '/preview']]) {
      expect(`${m} ${p} ${perm(m, p)}`).toBe(`${m} ${p} admin:write`)
    }
    expect(perm('GET', '/platform')).toBe('admin:read')
    expect(perm('GET', '/deleted')).toBe('admin:read')
    await admin.close()
  })

  it('an admin:write caller saves and requests, but cannot apply, even with MFA', async () => {
    const v = await saveAs(ADMIN)
    expect((await app.inject({ method: 'POST', url: '/sites/payroll/requests', headers: ADMIN, payload: { version: v } })).statusCode).toBe(201)
    const withMfa = { ...ADMIN, 'x-test-mfa': '1' }
    for (const [method, url, payload] of [
      ['POST', '/sites/payroll/apply', { version: v }], ['POST', '/sites/payroll/pause', {}], ['DELETE', '/sites/payroll', undefined],
      ['POST', '/sites/payroll/drift/accept', {}], ['POST', '/sites/migration/cutover', {}],
    ] as const) {
      expect((await app.inject({ method, url, headers: withMfa, ...(payload ? { payload } : {}) })).statusCode).toBe(403)
    }
    expect(cluster.crs.size).toBe(0)
  })

  it('a super admin applies with MFA, and not without', async () => {
    const v = await saveAs(ADMIN)
    const noMfa = { 'x-test-perms': SUPER['x-test-perms'] }
    expect((await app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: noMfa, payload: { version: v } })).statusCode).toBe(422)
    expect((await app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: SUPER, payload: { version: v } })).statusCode).toBe(200)
  })
})

describe('list: draft-only sites', () => {
  it('a site that only has a draft is listed as a draft at version 0, and goes when the draft is discarded', async () => {
    const draft = { name: 'ledger', displayName: 'Ledger', address: { host: 'ledger.dev.stairling.com' } }
    expect((await app.inject({ method: 'PUT', url: '/sites/ledger/draft', headers: ADMIN, payload: { site: draft } })).statusCode).toBe(200)
    await saveAs(ADMIN)
    const list = (await app.inject({ method: 'GET', url: '/sites' })).json() as Array<{ name: string }>
    expect(list.map((s) => s.name)).toEqual(['ledger', 'payroll'])
    expect(list[0]).toMatchObject({ name: 'ledger', displayName: 'Ledger', host: 'ledger.dev.stairling.com', status: 'draft', version: 0, draft: { by: 'sam@x.test', at: expect.any(String) } })
    await app.inject({ method: 'DELETE', url: '/sites/ledger/draft', headers: ADMIN })
    expect(((await app.inject({ method: 'GET', url: '/sites' })).json() as unknown[]).length).toBe(1)
  })

  it('a draft with no name or host yet is still listed', async () => {
    await app.inject({ method: 'PUT', url: '/sites/ledger/draft', headers: ADMIN, payload: { site: {} } })
    expect((await app.inject({ method: 'GET', url: '/sites' })).json()).toEqual([expect.objectContaining({ name: 'ledger', displayName: 'ledger', host: null, status: 'draft', version: 0 })])
  })

  it('saving the site takes it off the draft list', async () => {
    await app.inject({ method: 'PUT', url: '/sites/payroll/draft', headers: ADMIN, payload: { site: { name: 'payroll' } } })
    await saveAs(ADMIN)
    expect(redis.sets.get('rbac:sites:drafts')?.has('payroll') ?? false).toBe(false)
  })
})

describe('static reads', () => {
  it('/platform describes the environment', async () => {
    process.env.SITES_FOUR_EYES = 'high-risk'
    process.env.SITES_ENV = 'dev-aws-1'
    resetSitesConfig()
    const p = (await app.inject({ method: 'GET', url: '/sites/platform' })).json()
    expect(p).toMatchObject({ env: 'dev-aws-1', production: false, fourEyes: 'high-risk', rulesLoadExpectedSec: expect.any(Number) })
    expect(p.zones).toEqual([expect.objectContaining({ suffix: 'dev.stairling.com', sso: true, tls: 'wildcard' })])
    delete process.env.SITES_FOUR_EYES
    delete process.env.SITES_ENV
  })

  it('an unknown site keeps its exact 404', async () => {
    const res = await app.inject({ method: 'GET', url: '/sites/nope' })
    expect(res.statusCode).toBe(404)
    expect(res.json().message).toBe('Site not found: nope')
  })

  it('/requests lists requests', async () => {
    expect((await app.inject({ method: 'GET', url: '/sites/requests' })).json()).toEqual([])
  })
})

describe('deleted sites and restore', () => {
  it('a deleted site is listed with who and when, and restore brings its record and history back (not applied)', async () => {
    const v = await saveAs(ADMIN)
    await app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: SUPER, payload: { version: v } })
    expect((await app.inject({ method: 'DELETE', url: '/sites/payroll', headers: SUPER })).statusCode).toBe(200)
    const deleted = (await app.inject({ method: 'GET', url: '/sites/deleted' })).json()
    expect(deleted).toEqual([expect.objectContaining({ name: 'payroll', displayName: 'Payroll', host: 'payroll.dev.stairling.com', version: 1, deletedBy: 'sam@x.test', deletedAt: expect.any(String), expiresAt: expect.any(String) })])
    expect((await app.inject({ method: 'POST', url: '/sites/payroll/restore', headers: ADMIN })).statusCode).toBe(403)
    const res = await app.inject({ method: 'POST', url: '/sites/payroll/restore', headers: SUPER })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ name: 'payroll', version: 1, status: 'draft' })
    expect((await app.inject({ method: 'GET', url: '/sites/payroll/versions' })).json()).toHaveLength(1)
    expect((await app.inject({ method: 'GET', url: '/sites/deleted' })).json()).toEqual([])
  })

  it('restore refuses an unknown snapshot and a name in use', async () => {
    expect((await app.inject({ method: 'POST', url: '/sites/payroll/restore', headers: SUPER })).statusCode).toBe(404)
    const v = await saveAs(ADMIN)
    await app.inject({ method: 'DELETE', url: '/sites/payroll', headers: SUPER })
    await saveAs(ADMIN)
    expect(v).toBe(1)
    expect((await app.inject({ method: 'POST', url: '/sites/payroll/restore', headers: SUPER })).statusCode).toBe(409)
  })
})
