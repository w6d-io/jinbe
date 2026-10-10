import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { payrollSite, ACK } from './fixtures.js'
import { fakeGatekit } from './mocks.js'
import type { Site } from '../../sites/schemas.js'

// Sites nested on one host — a shell at the root, a portal at /cab, its API at /cab/api/pricing. The
// longest prefix wins: the enclosing site's catch-all leaves the nested prefixes out, a route of its
// own reaching into one is refused, and applying (or deleting) a nested site writes the enclosing
// site's rules again — first, so the gateway never holds two rules for one request.

const h = vi.hoisted(() => ({
  emit: vi.fn(),
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
vi.mock('../../middleware/require-admin.js', async () => {
  const { enforcing } = await import('../../policy/declared-routes.js')
  const pass = () => async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden' })
  }
  return { requireSuperAdmin: enforcing(pass(), 'admin:write'), requireSitesApply: enforcing(pass(), 'sites:apply'), requireRecentMfa: async () => {} }
})

import { sitesRoutes } from '../../sites/routes.js'
import { setKubeSites, type IngressHosts, type ZoneCrObject } from '../../sites/kube-sites.js'
import { setKubeGateway, type KubeGateway } from '../../gateway/kube-gateway.js'
import { resetSitesConfig } from '../../sites/config.js'
import { publicLoginByHost } from '../../sites/login.js'
import { hostOwner } from '../../sites/checks.js'
import { render } from '../../sites/render.js'
import { enclosingSites, nestedPrefixes, prefixContains } from '../../sites/nesting.js'
import { oathkeeperRegex, platform } from './fixtures.js'
import type { SiteRecord } from '../../sites/repository.js'
import * as redisClient from '../../services/redis-client.service.js'
import * as rbacRepo from '../../services/redis-rbac.repository.js'

type Store = ReturnType<typeof import('./mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('./mocks.js').InlineRedisMock }).__redis

const W = { 'x-test-write': '1' }
const cond = (type: string, status: string) => ({ type, status, reason: status === 'True' ? 'Ok' : 'Pending', message: '', observedGeneration: 1 })
const zone = (name: string, domain: string, ready: boolean): ZoneCrObject => ({
  metadata: { name, generation: 1, labels: { 'auth.w6d.io/zone-owner': 'auth' } }, spec: { domain }, status: { observedGeneration: 1, conditions: [cond('Ready', ready ? 'True' : 'False')] },
})
const ing = (namespace: string, name: string, hosts: string[], paths: string[] = ['/']): IngressHosts =>
  ({ namespace, name, hosts, labels: {}, paths: Object.fromEntries(hosts.map((x) => [x, paths])) })

type Cr = { metadata: { name: string }; spec: { hosts: string[]; gates: Array<{ name: string; match: { url: string } }> } }
const cluster = { zones: [] as ZoneCrObject[], ingresses: [] as IngressHosts[], applied: [] as Cr[], deleted: [] as string[] }
const kube = {
  ping: async () => {},
  get: async () => null,
  apply: async (cr: Cr) => { cluster.applied.push(structuredClone(cr)) },
  delete: async (name: string) => { cluster.deleted.push(name) },
  listZones: async () => structuredClone(cluster.zones),
  listIngresses: async () => structuredClone(cluster.ingresses),
}

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request) => { request.userContext = { id: 'sam-id', email: 'sam@x.test', name: 'Sam' } })
  await app.register(sitesRoutes, { prefix: '/sites' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  redis.clear()
  store.reset()
  h.emit.mockClear()
  h.gatekit.status = 200
  h.gatekit.calls = []
  h.gatekit.overlap = () => ({ overlaps: [] })
  cluster.zones = [zone('dev', 'dev.example.com', true), zone('apps', 'apps.stairfleet.com', false)]
  cluster.ingresses = []
  cluster.applied = []
  cluster.deleted = []
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_NAMESPACE = 'auth'
  process.env.SITES_KUBE = 'in-cluster'
  process.env.SITES_ZONES = '[]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.example.com'
  process.env.SITES_RESERVED_HOSTS = 'kuma.dev.example.com'
  process.env.SITES_ZONE_ALLOWED_PARENTS = 'example.com'
  resetSitesConfig()
  setKubeSites(kube as never)
  setKubeGateway({ get: async () => null, liveOathkeeperConfig: async () => null } as unknown as KubeGateway)
  vi.stubGlobal('fetch', fakeGatekit(h.gatekit))
})


const HOST = 'shell.dev.example.com'
const site = (name: string, pathPrefix?: string, overrides: Partial<Site> = {}) => payrollSite({
  name,
  address: { host: HOST, ...(pathPrefix ? { pathPrefix } : {}) },
  groups: { platform: {}, orgGrantable: {} },
  routes: { items: [], catchAll: { gate: 'web', access: { kind: 'signed-in' } } },
  ...overrides,
})
const shell = () => site('shell')
const cab = () => site('cab', '/cab')
const pricing = () => site('cab-pricing', '/cab/api/pricing')

/** Which of the CR's gates match the URL (the operator writes one Oathkeeper rule per gate). */
const matching = (cr: Cr, path: string) => cr.spec.gates.filter((g) => oathkeeperRegex(g.match.url).test(`https://${HOST}${path}`)).map((g) => g.name)
const crsOf = (name: string) => cluster.applied.filter((c) => c.metadata.name === name)
const lastCr = (name: string) => crsOf(name).at(-1)!

async function apply(s: Site) {
  expect((await saveSite(s)).statusCode).toBe(200)
  const res = await app.inject({ method: 'POST', url: `/sites/${s.name}/apply`, headers: W, payload: { version: 1, acknowledge: ACK } })
  expect(res.statusCode, res.body).toBe(200)
}
async function saveSite(s: Site) {
  return app.inject({ method: 'PUT', url: `/sites/${s.name}`, headers: W, payload: { site: s } })
}
const preview = async (s: Site) => app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site: s } })
const codes = (checks: Array<{ code: string; level: string }>, level?: string) => checks.filter((c) => !level || c.level === level).map((c) => c.code)

describe('nesting helpers', () => {
  it('a prefix sits under the root and under a shorter prefix, never under itself or a sibling', () => {
    expect(prefixContains(undefined, '/cab')).toBe(true)
    expect(prefixContains('/cab', '/cab/api/pricing')).toBe(true)
    expect(prefixContains('/cab', '/cab')).toBe(false)
    expect(prefixContains('/cab', '/cabinet')).toBe(false)
    expect(prefixContains('/cab', undefined)).toBe(false)
  })

  it('nested prefixes: applied sites on the same host only, at the address they serve now', () => {
    const rec = (s: Site, applied = true) => ({ site: s, version: 1, etag: 'e', savedAt: 't', savedBy: 's', ...(applied ? { applied: { version: 1, at: 't', by: 's', rules: [] } } : {}) }) as SiteRecord
    const other = payrollSite({ name: 'elsewhere', address: { host: 'other.dev.example.com', pathPrefix: '/cab' } })
    const records = [rec(shell()), rec(cab()), rec(pricing()), rec(site('draft', '/draft'), false), rec(other)]
    const live = new Map<string, Site['address']>()
    // The outermost only: /cab/api/pricing is left out with /cab.
    expect(nestedPrefixes(shell().address, 'shell', records, live)).toEqual(['/cab'])
    expect(nestedPrefixes(cab().address, 'cab', records, live)).toEqual(['/cab/api/pricing'])
    expect(nestedPrefixes(pricing().address, 'cab-pricing', records, live)).toEqual([])
    // A move not applied yet: the gateway still serves the live address.
    live.set('cab', { host: HOST, pathPrefix: '/old' })
    expect(nestedPrefixes(shell().address, 'shell', records, live)).toEqual(['/cab/api/pricing', '/old'])
    expect(enclosingSites(pricing().address, 'cab-pricing', records, new Map()).map((r) => r.site.name)).toEqual(['shell', 'cab'])
  })
})

describe('render with nested sites', () => {
  it('the catch-all leaves the nested prefixes out, for every method', () => {
    const r = render(shell(), platform, { nested: ['/cab', '/cab/api/pricing'] })
    expect(r.checks.filter((c) => c.level === 'error')).toEqual([])
    const cr = r.siteCr as unknown as Cr
    expect(matching(cr, '/')).not.toEqual([])
    expect(matching(cr, '/workers/x')).not.toEqual([])
    expect(matching(cr, '/cabinet')).not.toEqual([])
    expect(matching(cr, '/cab')).toEqual([])
    expect(matching(cr, '/cab/')).toEqual([])
    expect(matching(cr, '/cab/api/pricing/v1/x')).toEqual([])
  })

  it('a prefixed site leaves out what is nested under it, and keeps the rest of its prefix', () => {
    const cr = render(cab(), platform, { nested: ['/cab/api/pricing'] }).siteCr as unknown as Cr
    expect(matching(cr, '/cab/zones')).not.toEqual([])
    expect(matching(cr, '/cab/api/pricing/v1/x')).toEqual([])
    expect(matching(cr, '/elsewhere')).toEqual([])
  })

  it('a route of its own reaching into a nested prefix is refused', () => {
    const s = shell()
    s.routes.items = [{ id: 'cab-health', methods: ['GET'], path: '/cab/health', gate: 'public', access: { kind: 'public' }, source: 'manual' }]
    const errors = render(s, platform, { nested: ['/cab'] }).checks.filter((c) => c.level === 'error')
    expect(errors.map((c) => c.code)).toEqual(['route_in_nested_site'])
    expect(errors[0].message).toContain('/cab/health reaches into /cab')
  })

  it('without nested sites nothing changes', () => {
    expect(render(shell(), platform, {}).siteCr).toEqual(render(shell(), platform).siteCr)
  })
})

describe('render on a session zone (SITES_SESSION_ZONES)', () => {
  const sessionPlatform = { ...platform, sessionZones: ['dev.example.com'] }

  it('a site at the root leaves the session check to the platform, and only it', () => {
    const r = render(shell(), sessionPlatform, { nested: ['/cab'] })
    expect(r.checks.filter((c) => c.level === 'error')).toEqual([])
    const cr = r.siteCr as unknown as Cr
    expect(matching(cr, '/sessions/whoami')).toEqual([])
    expect(matching(cr, '/self-service/logout/browser')).toEqual([])
    expect(matching(cr, '/sessions/whoami/x')).not.toEqual([])
    expect(matching(cr, '/sessions')).not.toEqual([])
    expect(matching(cr, '/self-service/login/browser')).not.toEqual([])
    expect(matching(cr, '/cab/x')).toEqual([])
  })

  it('a route of its own taking a session path is refused', () => {
    const s = shell()
    s.routes.items = [{ id: 'sessions', methods: ['GET'], path: '/sessions/:any*', gate: 'public', access: { kind: 'public' }, source: 'manual' }]
    const errors = render(s, sessionPlatform).checks.filter((c) => c.level === 'error')
    expect(errors.map((c) => c.code)).toEqual(['route_on_session_path'])
    expect(errors[0].message).toContain('/sessions/whoami')
  })

  it('a prefixed site, a host outside the zones or deeper than one label: nothing changes', () => {
    expect(render(cab(), sessionPlatform).siteCr).toEqual(render(cab(), platform).siteCr)
    const elsewhere = { ...platform, sessionZones: ['qualif.example.com'] }
    expect(render(shell(), elsewhere).siteCr).toEqual(render(shell(), platform).siteCr)
    const deep = payrollSite({ name: 'deep', address: { host: 'a.b.dev.example.com' } })
    expect(render(deep, sessionPlatform).siteCr).toEqual(render(deep, platform).siteCr)
  })
})

describe('nested sites through save, preview and apply', () => {
  it('a nested prefix is not host_taken; the same prefix still is', async () => {
    await apply(shell())
    const res = await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: HOST, pathPrefix: '/cab', site: 'cab' } })
    if (res.statusCode === 200) expect(codes(res.json().checks ?? [])).not.toContain('host_taken')
    expect(hostOwner(HOST, '/cab', 'cab', [{ site: shell(), version: 1, etag: 'e', savedAt: 't', savedBy: 's', applied: { version: 1, at: 't', by: 's', rules: [] } } as SiteRecord]).owner).toBeUndefined()
    expect(hostOwner(HOST, undefined, 'other', [{ site: shell(), version: 1, etag: 'e', savedAt: 't', savedBy: 's', applied: { version: 1, at: 't', by: 's', rules: [] } } as SiteRecord]).owner).toBe('shell')
  })

  it('preview of a nested site runs gatekit against the enclosing site as it will be written', async () => {
    await apply(shell())
    h.gatekit.calls = []
    const res = await preview(cab())
    expect(res.statusCode).toBe(200)
    expect(codes(res.json().checks, 'error')).toEqual([])
    const overlap = h.gatekit.calls.find((c) => c.path === '/overlap')!
    const rules = overlap.body.rules as Array<{ id: string; match: { url: string } }>
    const shellRules = rules.filter((r) => r.id.startsWith('site-shell-'))
    expect(shellRules.length).toBeGreaterThan(0)
    expect(shellRules.some((r) => oathkeeperRegex(r.match.url).test(`https://${HOST}/cab/x`))).toBe(false)
  })

  it('taking a prefix from another site is said and must be confirmed (nested_in_site), naming that site', async () => {
    await apply(shell())
    const findings = (await preview(cab())).json().findings as Array<{ code: string; level: string; message: string }>
    expect(findings.find((f) => f.code === 'nested_in_site')).toMatchObject({ level: 'confirm', message: expect.stringContaining("'shell'") })
    await app.inject({ method: 'PUT', url: '/sites/cab', headers: W, payload: { site: cab() } })
    const without = ACK.filter((c) => c !== 'nested_in_site')
    const res = await app.inject({ method: 'POST', url: '/sites/cab/apply', headers: W, payload: { version: 1, acknowledge: without } })
    expect(res.statusCode).toBe(422)
    expect(JSON.stringify(res.json())).toContain('nested_in_site')
    // The enclosing site at the root is inside nobody: no such finding for it.
    expect(((await preview(shell())).json().findings as Array<{ code: string }>).some((f) => f.code === 'nested_in_site')).toBe(false)
  })

  it('applying a nested site writes the enclosing site again first, then its own rules', async () => {
    await apply(shell())
    expect(matching(lastCr('shell'), '/cab/x')).not.toEqual([])
    cluster.applied = []
    await apply(cab())
    expect(cluster.applied.map((c) => c.metadata.name)).toEqual(['shell', 'cab'])
    expect(matching(lastCr('shell'), '/cab/x')).toEqual([])
    expect(matching(lastCr('shell'), '/other')).not.toEqual([])
    expect(matching(lastCr('cab'), '/cab/x')).not.toEqual([])
    const audit = h.emit.mock.calls.map((c) => c[0]).find((e) => e.verb === 'apply' && e.details?.nested)
    expect(audit).toBeTruthy()
  })

  it('a deeper site re-writes only the enclosing sites whose rules change', async () => {
    await apply(shell())
    await apply(cab())
    cluster.applied = []
    await apply(pricing())
    // Both enclose /cab/api/pricing; the shell already left /cab out, so only cab changes.
    expect(cluster.applied.map((c) => c.metadata.name)).toEqual(['cab', 'cab-pricing'])
    expect(matching(lastCr('cab'), '/cab/api/pricing/v1/x')).toEqual([])
    expect(matching(lastCr('cab-pricing'), '/cab/api/pricing/v1/x')).not.toEqual([])
  })

  it('applying the enclosing site again keeps the nested prefixes out', async () => {
    await apply(shell())
    await apply(cab())
    const s = shell()
    s.displayName = 'Shell v2'
    const etag = (await app.inject({ method: 'GET', url: '/sites/shell', headers: W })).headers.etag as string
    const saved = await app.inject({ method: 'PUT', url: '/sites/shell', headers: { ...W, 'if-match': etag }, payload: { site: s } })
    expect(saved.statusCode).toBe(200)
    cluster.applied = []
    expect((await app.inject({ method: 'POST', url: '/sites/shell/apply', headers: W, payload: { version: 2, acknowledge: ACK } })).statusCode).toBe(200)
    expect(matching(lastCr('shell'), '/cab/x')).toEqual([])
  })

  it('an enclosing route reaching into the new prefix refuses the nested apply', async () => {
    const s = shell()
    s.routes.items = [{ id: 'cab-health', methods: ['GET'], path: '/cab/health', gate: 'public', access: { kind: 'public' }, source: 'manual' }]
    await apply(s)
    expect((await saveSite(cab())).statusCode).toBe(200)
    const res = await app.inject({ method: 'POST', url: '/sites/cab/apply', headers: W, payload: { version: 1, acknowledge: ACK } })
    expect(res.statusCode).toBe(409)
    expect(res.body).toContain("site 'shell'")
    expect(crsOf('cab')).toEqual([])
  })

  it('deleting the nested site gives its prefix back to the enclosing site', async () => {
    await apply(shell())
    await apply(cab())
    cluster.applied = []
    const res = await app.inject({ method: 'DELETE', url: '/sites/cab', headers: W })
    expect(res.statusCode, res.body).toBeLessThan(300)
    expect(cluster.deleted).toEqual(['cab'])
    expect(matching(lastCr('shell'), '/cab/x')).not.toEqual([])
  })
})
