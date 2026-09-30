import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'
import { payrollSite, ACK } from './fixtures.js'
import { fakeGatekit } from './mocks.js'

// The site lifecycle through an MCP key (a delegated caller acting as its holder): draft, diff,
// OpenAPI import, save a version — with sites:write in the key's scopes; apply, pause, resume — with
// sites:apply, on the REAL step-up guard, which a personal key satisfies with the second factor its
// holder proved when creating it (delegated-step-up.ts). Never a delete; in production no direct
// publish (the apply request is the way).

const h = vi.hoisted(() => ({
  emit: vi.fn(),
  kube: { ping: vi.fn(), get: vi.fn(async () => null), apply: vi.fn(), delete: vi.fn(), listZones: vi.fn(async () => []) },
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
vi.mock('../../services/org-grants.repository.js', () => ({ orgGrantsRepository: { getAll: vi.fn(async () => ({})) } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../audit/deny.js', () => ({ denyAudit: vi.fn() }))
// The USER's rights come from a header; the step-up guard (require-admin.ts) is the real one.
vi.mock('../../middleware/require-permission.js', async () => (await import('../helpers/permission-stand-ins.js')).permissionStandIn())

import { installRouteAccess } from '../../policy/route-access.js'
import { delegationGate } from '../../middleware/delegation-gate.js'
import { sitesRoutes } from '../../sites/routes.js'
import { setKubeSites } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import * as redisClient from '../../services/redis-client.service.js'
import * as rbacRepo from '../../services/redis-rbac.repository.js'

type Store = ReturnType<typeof import('./mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('./mocks.js').InlineRedisMock }).__redis

const SPEC = `openapi: 3.0.3
info: { title: Invoices, version: '3.2' }
paths:
  /orgs/{orgId}/invoices:
    get: { operationId: listInvoices, tags: [invoices] }
`

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const scopes = String(request.headers['x-scopes'] ?? '')
    const kind = (request.headers['x-kind'] as 'personal' | 'oauth' | undefined) ?? 'personal'
    const stepUpAt = request.headers['x-key-step-up'] as string | undefined
    request.userContext = {
      id: 'sam-id', email: 'sam@x.test', name: 'Sam', authVia: 'delegated',
      delegation: { clientId: 'claude', scopes: scopes.split(' ').filter(Boolean), kind, via: 'auth-mcp', ...(stepUpAt ? { keyStepUpAt: stepUpAt } : {}) },
    } as never
  })
  app.addHook('preHandler', delegationGate)
  await app.register(sitesRoutes, { prefix: '/api/admin/sites' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  redis.clear()
  store.reset()
  h.gatekit.status = 200
  h.gatekit.calls = []
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_KUBE = 'off'
  process.env.SITES_ZONES = '[{"suffix":"dev.example.com","wildcardTls":true,"exposure":"ingress"}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.example.com'
  process.env.SITES_RESERVED_HOSTS = 'kuma.dev.example.com'
  delete process.env.SITES_PRODUCTION
  resetSitesConfig()
  h.kube.apply.mockReset()
  setKubeSites(h.kube as never)
  vi.stubGlobal('fetch', fakeGatekit(h.gatekit))
})

// The holder holds everything a publisher holds; the KEY narrows it with its scopes.
const USER = 'sites:read,sites:write,sites:apply'
const FRESH = () => new Date(Date.now() - 24 * 3600 * 1000).toISOString()
const key = (scopes: string, extra: Record<string, string> = {}) => ({ 'x-test-perms': USER, 'x-scopes': scopes, ...extra })
const WRITE = key('sites:read sites:write')
const PUBLISH = () => key('sites:read sites:write sites:apply', { 'x-key-step-up': FRESH() })

const inject = (method: 'GET' | 'PUT' | 'POST' | 'DELETE', url: string, headers: Record<string, string>, payload?: object) =>
  app.inject({ method, url: `/api/admin/sites${url}`, headers, ...(payload ? { payload } : {}) })

describe('drafting with sites:write', () => {
  it('saves and reads a draft, diffs, saves a version', async () => {
    expect((await inject('PUT', '/payroll/draft', WRITE, { site: { name: 'payroll' }, baseVersion: 0 })).statusCode).toBe(200)
    expect((await inject('GET', '/payroll/draft', WRITE)).statusCode).toBe(200)
    const saved = await inject('PUT', '/payroll', WRITE, { site: payrollSite(), note: 'from the assistant' })
    expect(saved.statusCode).toBe(200)
    expect(saved.json()).toMatchObject({ name: 'payroll', version: 1 })
    expect((await inject('POST', '/payroll/diff', WRITE, {})).statusCode).toBe(200)
  })

  it('imports an OpenAPI document into the draft (preview, then commit)', async () => {
    await inject('PUT', '/payroll', WRITE, { site: payrollSite() })
    const p = await inject('POST', '/payroll/import/preview', WRITE, { source: { content: SPEC } })
    expect(p.statusCode).toBe(200)
    const { spec, base } = p.json()
    const c = await inject('POST', '/payroll/import/commit', WRITE, { specSha256: spec.sha256, baseEtag: base.etag, acceptDenied: true })
    expect(c.statusCode).toBe(200)
    expect(redis.strings.has('rbac:sites:draft:payroll')).toBe(true)
  })

  // e2e AU-R-D1/D2/D5: the draft emitted nothing, and the import and save named the user without the key.
  it('audits the draft, the import and the save, naming the key beside its holder', async () => {
    h.emit.mockClear()
    await inject('PUT', '/payroll/draft', WRITE, { site: { name: 'payroll' }, baseVersion: 0 })
    await inject('PUT', '/payroll', WRITE, { site: payrollSite() })
    const p = await inject('POST', '/payroll/import/preview', WRITE, { source: { content: SPEC } })
    const { spec, base } = p.json()
    await inject('POST', '/payroll/import/commit', WRITE, { specSha256: spec.sha256, baseEtag: base.etag, acceptDenied: true })
    await new Promise((r) => setTimeout(r, 0))
    const events = h.emit.mock.calls.map(([e]) => e as { verb: string; actor: { id: string; act?: unknown } })
    expect(events.map((e) => e.verb)).toEqual(expect.arrayContaining(['draft', 'update', 'import']))
    for (const e of events.filter((x) => ['draft', 'update', 'import'].includes(x.verb))) {
      expect(e.actor).toMatchObject({ id: 'sam-id', act: { client_id: 'claude', via: 'auth-mcp', kind: 'personal' } })
    }
  })

  it('a key without sites:write drafts nothing, whatever its holder holds', async () => {
    const res = await inject('PUT', '/payroll/draft', key('sites:read'), { site: { name: 'payroll' } })
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ code: 'insufficient_scope', reason: 'scope_missing:sites:write' })
  })

  it('never deletes: not a draft, not a site', async () => {
    await inject('PUT', '/payroll/draft', WRITE, { site: { name: 'payroll' } })
    for (const url of ['/payroll/draft', '/payroll']) {
      const res = await inject('DELETE', url, key('sites:read sites:write sites:apply', { 'x-key-step-up': FRESH() }))
      expect(res.statusCode).toBe(403)
      expect(res.json().code).toBe('delegation_refused')
    }
  })
})

describe('publishing with sites:apply and the key\'s step-up', () => {
  it('applies, pauses and resumes on a personal key carrying its creation-time second factor', async () => {
    await inject('PUT', '/payroll', WRITE, { site: payrollSite() })
    const applied = await inject('POST', '/payroll/apply', PUBLISH(), { version: 1, acknowledge: ACK })
    expect(applied.statusCode).toBe(200)
    expect(h.kube.apply).toHaveBeenCalled()
    expect((await inject('POST', '/payroll/pause', PUBLISH())).statusCode).toBe(200)
    expect((await inject('POST', '/payroll/resume', PUBLISH())).statusCode).toBe(200)
  })

  it('without the key\'s step-up (none, too old, or an OAuth token), apply answers step_up_unavailable', async () => {
    await inject('PUT', '/payroll', WRITE, { site: payrollSite() })
    const old = new Date(Date.now() - 31 * 24 * 3600 * 1000).toISOString()
    for (const headers of [
      key('sites:read sites:write sites:apply'),
      key('sites:read sites:write sites:apply', { 'x-key-step-up': old }),
      key('sites:read sites:write sites:apply', { 'x-key-step-up': FRESH(), 'x-kind': 'oauth' }),
    ]) {
      const res = await inject('POST', '/payroll/apply', headers, { version: 1, acknowledge: ACK })
      expect(res.statusCode).toBe(422)
      expect(res.json().error).toBe('step_up_unavailable')
    }
    expect(h.kube.apply).not.toHaveBeenCalled()
  })

  it('a key without sites:apply publishes nothing', async () => {
    await inject('PUT', '/payroll', WRITE, { site: payrollSite() })
    const res = await inject('POST', '/payroll/apply', key('sites:read sites:write', { 'x-key-step-up': FRESH() }), { version: 1, acknowledge: ACK })
    expect(res.statusCode).toBe(403)
    expect(res.json().reason).toBe('scope_missing:sites:apply')
  })

  it('in production a key does not publish directly: the apply request is the way', async () => {
    await inject('PUT', '/payroll', WRITE, { site: payrollSite() })
    process.env.SITES_PRODUCTION = 'true'
    resetSitesConfig()
    const res = await inject('POST', '/payroll/apply', PUBLISH(), { version: 1, acknowledge: ACK })
    expect(res.statusCode).toBe(403)
    expect(res.json().reason).toBe('delegation_refused:use_apply_request')
    expect((await inject('POST', '/payroll/requests', WRITE, {})).statusCode).not.toBe(403)
  })
})
