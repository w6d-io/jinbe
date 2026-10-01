import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { installRouteAccess } from '../../../policy/route-access.js'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { readFileSync } from 'node:fs'
import { payrollSite } from '../fixtures.js'
import { fakeGatekit } from '../mocks.js'

// W2: POST /sites/:name/import/preview (reads, writes nothing but the upload for 24 h) and
// /import/commit (writes the DRAFT only; the sha must be the previewed one, the base the previewed one).

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

vi.mock('../../../services/redis-client.service.js', async () => {
  const { InlineRedisMock } = await import('../mocks.js')
  const redis = new InlineRedisMock()
  return { getRedisClient: () => redis, __redis: redis }
})
vi.mock('../../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => Promise<unknown>) => fn() }))
vi.mock('../../../services/redis-rbac.repository.js', async () => {
  const { makeRbacStore } = await import('../mocks.js')
  const store = makeRbacStore()
  return { redisRbacRepository: store.repo, __store: store }
})
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { invalidateBundle: vi.fn() } }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../../middleware/require-permission.js', async () => (await import('../../helpers/permission-stand-ins.js')).permissionStandIn())
vi.mock('../../../middleware/require-admin.js', async () => (await import('../../helpers/permission-stand-ins.js')).adminStandIn({ stepUpOpen: true }))

import { sitesRoutes } from '../../../sites/routes.js'
import { setKubeSites } from '../../../sites/kube-sites.js'
import { resetSitesConfig } from '../../../sites/config.js'
import * as redisClient from '../../../services/redis-client.service.js'
import * as rbacRepo from '../../../services/redis-rbac.repository.js'
import { declaredRoutes, resetDeclaredRoutes } from '../../../policy/declared-routes.js'

type Store = ReturnType<typeof import('../mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('../mocks.js').InlineRedisMock }).__redis
const W = { 'x-test-write': '1' }
const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8')

const SPEC = `openapi: 3.0.3
info: { title: Invoices, version: '3.2' }
servers: [{ url: 'https://invoices.internal.example/api' }]
paths:
  /orgs/{orgId}/invoices:
    get: { operationId: listInvoices, tags: [invoices] }
    post: { operationId: createInvoice, tags: [invoices] }
  /orgs/{orgId}/invoices/{id}:
    delete: { operationId: deleteInvoice, tags: [invoices] }
  /status:
    get: { operationId: status, tags: [status], security: [] }
`

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    request.userContext = { id: 'sam-id', email: 'sam@x.test', name: 'Sam' }
  })
  await app.register(sitesRoutes, { prefix: '/sites' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  redis.clear()
  store.reset()
  h.emit.mockReset()
  h.kube.apply.mockReset()
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_KUBE = 'off'
  process.env.SITES_ZONES = '[{"suffix":"dev.example.com","wildcardTls":true}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.example.com'
  delete process.env.SITES_MAX_ROUTES
  resetSitesConfig()
  setKubeSites(h.kube as never)
  vi.stubGlobal('fetch', fakeGatekit(h.gatekit))
})

const save = () => app.inject({ method: 'PUT', url: '/sites/payroll', headers: W, payload: { site: payrollSite(), note: 'v1' } })
const preview = (content: string, extra: Record<string, unknown> = {}, headers: Record<string, string> = W) =>
  app.inject({ method: 'POST', url: '/sites/payroll/import/preview', headers, payload: { source: { content }, ...extra } })
const commit = (payload: Record<string, unknown>) => app.inject({ method: 'POST', url: '/sites/payroll/import/commit', headers: W, payload })

describe('guards', () => {
  it('both routes need sites:write, like a draft save', async () => {
    resetDeclaredRoutes()
    const admin = Fastify()
    installRouteAccess(admin)
    await admin.register(sitesRoutes, { prefix: '/api/admin/sites' })
    await admin.ready()
    const find = (path: string) => declaredRoutes().find((r) => r.method === 'POST' && r.path === path)?.permission
    expect(find('/api/admin/sites/:name/import/preview')).toBe('sites:write')
    expect(find('/api/admin/sites/:name/import/commit')).toBe('sites:write')
    await admin.close()
  })

  it('refuses without sites:write and stores nothing', async () => {
    await save()
    const before = redis.strings.size
    expect((await preview(SPEC, {}, {})).statusCode).toBe(403)
    expect(redis.strings.size).toBe(before)
  })
})

describe('preview', () => {
  it('404 before the site exists', async () => {
    expect((await preview(SPEC)).json()).toMatchObject({ error: 'not_found' })
  })

  it('refuses a URL source until the fetch fence exists (W3)', async () => {
    await save()
    const res = await app.inject({ method: 'POST', url: '/sites/payroll/import/preview', headers: W, payload: { source: { url: 'http://169.254.169.254/latest/meta-data' } } })
    expect(res.statusCode).toBe(422)
    expect(res.json().error).toBe('url_import_disabled')
  })

  it('refuses a malicious spec with its code (through the worker)', async () => {
    await save()
    const res = await preview(fixture('ref-sa-token.yaml'))
    expect(res.statusCode).toBe(422)
    expect(res.json().error).toBe('external_ref')
  })

  it('proposes routes, writes no draft and no version', async () => {
    await save()
    const res = await preview(SPEC)
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.spec).toMatchObject({ title: 'Invoices', version: '3.2', format: '3.0', basePaths: ['/api'], hosts: ['invoices.internal.example'] })
    expect(body.spec.sha256).toMatch(/^[a-f0-9]{64}$/)
    expect(body.base).toMatchObject({ from: 'saved', complete: true })
    expect(body.rows.find((r: { op: string }) => r.op === 'listInvoices').route).toMatchObject({ path: '/api/orgs/:orgId/invoices', gate: 'web', orgParam: 'orgId', access: { kind: 'permission', permission: 'invoices:list' } })
    expect(body.rows.find((r: { op: string }) => r.op === 'status')).toMatchObject({ route: { access: { kind: 'permission' } }, suggestion: { access: { kind: 'public' } } })
    expect(body.reimport).toMatchObject({ added: 4 })
    expect(body.caps).toMatchObject({ maxRoutes: 500, routes: 7, maxEnumerated: 100 })
    expect(body.checks.filter((c: { level: string }) => c.level === 'error')).toEqual([])
    expect(redis.strings.has('rbac:sites:draft:payroll')).toBe(false)
    expect(redis.lists.get('rbac:sites:versions:payroll')).toHaveLength(1)
    expect(JSON.parse(redis.strings.get('rbac:sites:import:payroll')!).sha256).toBe(body.spec.sha256)
  })
})

describe('preview size', () => {
  it('reads a 1.5 MB spec over HTTP (far above the 200 KB the MCP tool sends), capped by operations, not bytes', async () => {
    await save()
    const doc = 'x'.repeat(4000)
    const paths = Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`/api/things${i}`, { get: { operationId: `thing${i}`, description: doc, responses: { '200': { description: 'ok' } } } }]))
    const content = JSON.stringify({ openapi: '3.0.0', info: { title: 'Big', version: '1' }, paths })
    expect(Buffer.byteLength(content)).toBeGreaterThan(1_200_000)
    const res = await preview(content)
    expect(res.statusCode).toBe(200)
    expect(res.json().spec.counts).toMatchObject({ operations: 300 })
  })

  it('refuses more operations than the parse cap with its code', async () => {
    await save()
    const paths = Object.fromEntries(Array.from({ length: 2001 }, (_, i) => [`/p${i}`, { get: { responses: {} } }]))
    const res = await preview(JSON.stringify({ openapi: '3.0.0', info: { title: 'Many', version: '1' }, paths }))
    expect(res.statusCode).toBe(422)
    expect(['too_many_paths', 'too_many_operations']).toContain(res.json().error)
  })
})

describe('commit', () => {
  it('409 for a sha that was not previewed', async () => {
    await save()
    const res = await commit({ specSha256: 'a'.repeat(64), baseEtag: '0'.repeat(16) })
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toBe('spec_not_previewed')
  })

  it('409 for a spec that is no longer the last one previewed for the site', async () => {
    await save()
    const first = (await preview(SPEC)).json()
    await preview(fixture('petstore-3.0.yaml'))
    const res = await commit({ specSha256: first.spec.sha256, baseEtag: first.base.etag })
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toBe('spec_not_previewed')
  })

  it('409 when the draft changed since the preview', async () => {
    await save()
    const p = (await preview(SPEC)).json()
    await app.inject({ method: 'PUT', url: '/sites/payroll/draft', headers: W, payload: { site: { ...payrollSite(), displayName: 'Changed' } } })
    const res = await commit({ specSha256: p.spec.sha256, baseEtag: p.base.etag })
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toBe('stale_base')
  })

  it('422 until what lowers protection is confirmed', async () => {
    await save()
    const p = (await preview(SPEC)).json()
    const res = await commit({ specSha256: p.spec.sha256, baseEtag: p.base.etag, decisions: [{ op: 'status', access: { kind: 'public' } }] })
    expect(res.statusCode).toBe(422)
    expect(res.json()).toMatchObject({ error: 'import_blocked', checks: [{ code: 'confirmation_required', path: 'status' }] })
    expect(redis.strings.has('rbac:sites:draft:payroll')).toBe(false)
  })

  it('writes the draft only (no version, no apply), audits site.imported, and the draft saves', async () => {
    await save()
    const p = (await preview(SPEC)).json()
    const res = await commit({ specSha256: p.spec.sha256, baseEtag: p.base.etag, decisions: [{ op: 'status', access: { kind: 'public' }, confirm: true }] })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ changed: true, counts: { added: 4, overrides: 1 } })
    const draft = JSON.parse(redis.strings.get('rbac:sites:draft:payroll')!)
    expect(draft.site.routes.openapi).toMatchObject({ sha256: p.spec.sha256, title: 'Invoices', version: '3.2', source: 'upload', importedBy: 'sam@x.test' })
    expect(draft.site.routes.items).toHaveLength(7)
    expect(draft.site.routes.items.find((r: { op?: string }) => r.op === 'status')).toMatchObject({ access: { kind: 'public' }, gate: 'public', pinned: true })
    expect(redis.lists.get('rbac:sites:versions:payroll')).toHaveLength(1)
    expect(h.kube.apply).not.toHaveBeenCalled()
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ verb: 'import', target: 'site:payroll', details: expect.objectContaining({ sha256: p.spec.sha256, riskFlags: expect.arrayContaining(['spec_lowers_protection']) }) }))

    const etag = (await app.inject({ method: 'GET', url: '/sites/payroll' })).json().etag
    const saved = await app.inject({ method: 'PUT', url: '/sites/payroll', headers: { ...W, 'if-match': `"${etag}"` }, payload: { site: draft.site } })
    expect(saved.statusCode).toBe(200)
  })

  it('a high-risk row needs its own confirm: a tie with another service blocks until confirmed', async () => {
    await save()
    store.s.services.add('billing')
    store.s.routeMaps.billing = { rules: [{ method: 'GET', path: '/api/orgs/:orgId/invoices', permission: 'billing:read' }] } as never
    const p = (await preview(SPEC)).json()
    const row = p.rows.find((r: { op: string }) => r.op === 'listInvoices')
    expect(row).toMatchObject({ needsConfirm: true, blocking: { code: 'risk_unconfirmed' } })
    expect(row.risk.map((f: { code: string }) => f.code)).toContain('route_tie')
    const refused = await commit({ specSha256: p.spec.sha256, baseEtag: p.base.etag })
    expect(refused.statusCode).toBe(422)
    expect(refused.json().checks).toEqual([expect.objectContaining({ code: 'risk_unconfirmed', path: 'listInvoices' })])
    const ok = await commit({ specSha256: p.spec.sha256, baseEtag: p.base.etag, decisions: [{ op: 'listInvoices', confirm: true }] })
    expect(ok.statusCode).toBe(200)
    // A confirm alone decides nothing: the route stays as proposed, not pinned.
    const draft = JSON.parse(redis.strings.get('rbac:sites:draft:payroll')!)
    expect(draft.site.routes.items.find((r: { op?: string }) => r.op === 'listInvoices').pinned).toBeUndefined()
  })

  it('a public write on an admin path, lowered on the spec\'s word, is committed only once confirmed', async () => {
    await save()
    const p = (await preview(fixture('public-delete-admin.yaml'))).json()
    // Proposed as a permission: nothing risky yet, only a suggestion rated high.
    expect(p.rows[0].needsConfirm).toBeUndefined()
    const decided = await commit({ specSha256: p.spec.sha256, baseEtag: p.base.etag, decisions: [{ op: 'deleteUser', access: { kind: 'public' }, confirm: true }] })
    expect(decided.statusCode).toBe(200)
    expect(decided.json().risk.level).toBe('high')
  })

  it('re-importing the same spec is a no-op', async () => {
    await save()
    const p1 = (await preview(SPEC)).json()
    await commit({ specSha256: p1.spec.sha256, baseEtag: p1.base.etag })
    const p2 = (await preview(SPEC)).json()
    expect(p2.sameSpec).toBe(true)
    expect(p2.reimport).toMatchObject({ added: 0, changed: 0, removed: 0, unchanged: 4 })
    const res = await commit({ specSha256: p2.spec.sha256, baseEtag: p2.base.etag })
    expect(res.json()).toMatchObject({ changed: false })
  })

  it('refuses past SITES_MAX_ROUTES', async () => {
    process.env.SITES_MAX_ROUTES = '5'
    resetSitesConfig()
    // The saved site has 3 routes; the cap is checked on what the import would make.
    await app.inject({ method: 'PUT', url: '/sites/payroll/draft', headers: W, payload: { site: payrollSite() } })
    const p = (await preview(SPEC)).json()
    expect(p.blocking.map((b: { code: string }) => b.code)).toContain('too_many_routes')
    const res = await commit({ specSha256: p.spec.sha256, baseEtag: p.base.etag })
    expect(res.statusCode).toBe(422)
  })
})
