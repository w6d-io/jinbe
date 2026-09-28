import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { payrollSite } from './fixtures.js'
import { fakeGatekit } from './mocks.js'
import type { Site } from '../../sites/schemas.js'

// Moving a live site: host label, zone and path prefix change through save → preview → apply. Every
// check runs against the NEW address; the move itself is said (address_changed, high risk), the
// landing page left on the old host is offered its fix, the operator's rule-by-rule rewrite is asked
// of gatekit on both addresses, and until the move is applied the old address stays the site's.

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
import { gateOfRule, movedUrl } from '../../sites/address.js'
import type { SiteRecord } from '../../sites/repository.js'
import * as redisClient from '../../services/redis-client.service.js'
import * as rbacRepo from '../../services/redis-rbac.repository.js'

type Store = ReturnType<typeof import('./mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('./mocks.js').InlineRedisMock }).__redis

const W = { 'x-test-write': '1' }
const cond = (type: string, status: string) => ({ type, status, reason: status === 'True' ? 'Ok' : 'Pending', message: '', observedGeneration: 1 })
const zone = (name: string, domain: string, ready: boolean): ZoneCrObject => ({
  metadata: { name, generation: 1 }, spec: { domain }, status: { observedGeneration: 1, conditions: [cond('Ready', ready ? 'True' : 'False')] },
})
const ing = (namespace: string, name: string, hosts: string[], paths: string[] = ['/']): IngressHosts =>
  ({ namespace, name, hosts, labels: {}, paths: Object.fromEntries(hosts.map((x) => [x, paths])) })

const cluster = { zones: [] as ZoneCrObject[], ingresses: [] as IngressHosts[], applied: [] as Array<{ spec: { hosts: string[] } }> }
const kube = {
  ping: async () => {},
  get: async () => null,
  apply: async (cr: { spec: { hosts: string[] } }) => { cluster.applied.push(structuredClone(cr)) },
  delete: async () => {},
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

const echo = (overrides: Partial<Site> = {}) => payrollSite({ name: 'echo', address: { host: 'echo-sandbox.dev.example.com' }, groups: { platform: {}, orgGrantable: {} }, ...overrides })
const moved = (host: string, extra: Partial<Site> = {}) => echo({ address: { host }, ...extra })

async function saveSite(site: Site, etag?: string) {
  return app.inject({ method: 'PUT', url: `/sites/${site.name}`, headers: { ...W, ...(etag ? { 'if-match': etag } : {}) }, payload: { site } })
}
/** echo, saved and applied at version 1 on echo-sandbox.dev.example.com. */
async function live(site = echo()) {
  const saved = await saveSite(site)
  expect((await app.inject({ method: 'POST', url: `/sites/${site.name}/apply`, headers: W, payload: { version: 1 } })).statusCode).toBe(200)
  return saved.headers.etag as string
}
const preview = async (site: Site) => app.inject({ method: 'POST', url: '/sites/preview', headers: W, payload: { site } })
const codes = (checks: Array<{ code: string; level: string }>, level?: string) => checks.filter((c) => !level || c.level === level).map((c) => c.code)
const settle = () => new Promise((r) => setTimeout(r, 0))

describe('preview of a moved address', () => {
  it('says the move old → new, bumps the risk, and runs gatekit against the new host', async () => {
    await live()
    h.gatekit.calls = []
    const res = await preview(moved('something-else.dev.example.com'))
    expect(res.statusCode).toBe(200)
    const body = res.json()
    const change = body.checks.find((c: { code: string }) => c.code === 'address_changed')
    expect(change).toMatchObject({
      level: 'warn',
      address: { from: { host: 'echo-sandbox.dev.example.com', zone: 'dev.example.com', url: 'https://echo-sandbox.dev.example.com/' }, to: { host: 'something-else.dev.example.com', zone: 'dev.example.com' } },
    })
    expect(change.message).toContain('OAuth redirect URIs')
    expect(body.risk.level).toBe('high')
    expect(body.risk.flags.map((f: { code: string }) => f.code)).toContain('host_changed')
    const [overlap, swap] = h.gatekit.calls.filter((c) => c.path === '/overlap')
    expect(overlap.body.hosts).toEqual(['something-else.dev.example.com'])
    expect((overlap.body.probes as Array<{ url: string }>).every((p) => p.url.startsWith('https://something-else.dev.example.com/'))).toBe(true)
    // The rewrite moment: old rules next to the new ones, probed on both hosts.
    expect(swap.body.hosts).toEqual(['something-else.dev.example.com', 'echo-sandbox.dev.example.com'])
    expect(codes(body.checks, 'error')).toEqual([])
  })

  it('a site never applied has nothing live to break: no address_changed', async () => {
    await saveSite(echo())
    const body = (await preview(moved('something-else.dev.example.com'))).json()
    expect(codes(body.checks)).not.toContain('address_changed')
  })

  it('a new zone: moved zone named, a zone not ready and outside the allowed parents is warned, SSO lost is warned', async () => {
    await live()
    const body = (await preview(moved('echo.apps.stairfleet.com'))).json()
    const change = body.checks.find((c: { code: string }) => c.code === 'address_changed')
    expect(change.message).toContain('zone dev.example.com → apps.stairfleet.com')
    expect(codes(body.checks, 'warn')).toEqual(expect.arrayContaining(['zone_not_ready', 'zone_parent_not_allowed', 'no_sso']))
  })

  it('an address outside every zone, too deep, reserved, or another site\'s is refused', async () => {
    await live()
    await saveSite(payrollSite())
    const errors = async (host: string) => codes((await preview(moved(host))).json().checks, 'error')
    expect(await errors('echo.example.org')).toContain('host_outside_zones')
    expect(await errors('a.b.dev.example.com')).toContain('host_too_deep')
    expect(await errors('kuma.dev.example.com')).toContain('host_reserved')
    expect(await errors('payroll.dev.example.com')).toContain('host_taken')
  })

  it('another Ingress on the new host is host_taken; a wildcard it would shadow is warned', async () => {
    await live()
    cluster.ingresses = [ing('tools', 'grafana', ['grafana.dev.example.com']), ing('web', 'www', ['*.apps.stairfleet.com'], ['/collect'])]
    expect(codes((await preview(moved('grafana.dev.example.com'))).json().checks, 'error')).toContain('host_taken')
    expect(codes((await preview(moved('echo.apps.stairfleet.com'))).json().checks, 'warn')).toContain('host_shadows_wildcard')
  })

  it('an overlap on the new host with any live rule, legacy included, is an error', async () => {
    await live()
    h.gatekit.calls = []
    store.s.accessRules = [{ id: 'legacy-web', upstream: { url: 'http://x' }, match: { url: '<https?>://something-else.dev.example.com/<.*>', methods: ['GET'] }, authenticators: [], authorizer: { handler: 'allow' }, mutators: [] }]
    h.gatekit.overlap = (body: unknown) => {
      const rules = (body as { rules: Array<{ id: string }> }).rules
      return rules.some((r) => r.id === 'legacy-web') ? { overlaps: [{ a: rules.at(-1)!.id, b: 'legacy-web', method: 'GET', exampleUrl: 'https://something-else.dev.example.com/' }] } : { overlaps: [] }
    }
    const body = (await preview(moved('something-else.dev.example.com'))).json()
    const overlap = h.gatekit.calls.find((c) => c.path === '/overlap')!
    expect((overlap.body.rules as Array<{ id: string }>).map((r) => r.id)).toContain('legacy-web')
    expect(codes(body.checks, 'error')).toContain('rule_overlap')
  })

  it('the landing page left on the old host: one error, carrying the rewritten URL; save refuses until it is fixed', async () => {
    const withLanding = (host: string, url: string) => moved(host, { login: { twoFactor: { scope: 'none', clients: 'exempt' }, reach: 'granted', defaultReturnUrl: url } })
    const etag = await live(withLanding('echo-sandbox.dev.example.com', 'https://echo-sandbox.dev.example.com/home?tab=1'))
    const body = (await preview(withLanding('something-else.dev.example.com', 'https://echo-sandbox.dev.example.com/home?tab=1'))).json()
    const landing = body.checks.filter((c: { path?: string }) => c.path === 'login.defaultReturnUrl')
    expect(landing).toEqual([expect.objectContaining({ level: 'error', code: 'return_url_old_address', fix: { path: 'login.defaultReturnUrl', value: 'https://something-else.dev.example.com/home?tab=1' } })])
    expect((await saveSite(withLanding('something-else.dev.example.com', 'https://echo-sandbox.dev.example.com/home?tab=1'), etag)).statusCode).toBe(422)
    expect((await saveSite(withLanding('something-else.dev.example.com', 'https://something-else.dev.example.com/home?tab=1'), etag)).statusCode).toBe(200)
  })

  it('a prefix change is high risk, and a landing page outside the new prefix is warned', async () => {
    await live(echo({ address: { host: 'echo-sandbox.dev.example.com', pathPrefix: '/api' }, routes: { items: [], catchAll: { gate: 'web', access: { kind: 'signed-in' } } } }))
    const next = echo({
      address: { host: 'echo-sandbox.dev.example.com', pathPrefix: '/v2' }, routes: { items: [], catchAll: { gate: 'web', access: { kind: 'signed-in' } } },
      login: { twoFactor: { scope: 'none', clients: 'exempt' }, reach: 'granted', defaultReturnUrl: 'https://echo-sandbox.dev.example.com/api/home' },
    })
    const body = (await preview(next)).json()
    expect(body.risk.flags.map((f: { code: string }) => f.code)).toContain('prefix_changed')
    expect(codes(body.checks, 'warn')).toEqual(expect.arrayContaining(['address_changed', 'return_url_outside_prefix']))
  })

  it('two different gates matching one URL during the rewrite is an error; the same gate rewritten in place is not', async () => {
    await live()
    const site = moved('something-else.dev.example.com')
    const old = (await app.inject({ method: 'GET', url: '/sites/echo' })).json().applied.rules as string[]
    const oldWeb = old.find((id) => gateOfRule('echo', id) === 'web')!
    const oldPublic = old.find((id) => gateOfRule('echo', id) === 'public')!
    const answer = (sameGate: boolean) => (body: unknown) => {
      const rules = (body as { rules: Array<{ id: string }>; hosts: string[] }).rules
      if ((body as { hosts: string[] }).hosts.length < 2) return { overlaps: [] }
      const fresh = rules.filter((r) => !old.includes(r.id))
      const now = fresh.find((r) => gateOfRule('echo', r.id) === (sameGate ? 'public' : 'web'))!
      return { overlaps: [{ a: oldPublic, b: now.id, method: 'GET', exampleUrl: 'https://something-else.dev.example.com/health' }] }
    }
    h.gatekit.overlap = answer(false)
    expect(codes((await preview(site)).json().checks, 'error')).toContain('swap_overlap')
    h.gatekit.overlap = answer(true)
    expect(codes((await preview(site)).json().checks, 'error')).not.toContain('swap_overlap')
    expect(oldWeb).toBeDefined()
  })
})

describe('check-host while a move is pending', () => {
  it('the old address stays the moving site\'s until its move is applied', async () => {
    const etag = await live()
    await saveSite(moved('something-else.dev.example.com'), etag)
    const res = (await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'echo-sandbox.dev.example.com', site: 'other' } })).json()
    expect(res.available).toBe(false)
    expect(res.checks.find((c: { code: string }) => c.code === 'host_taken').message).toContain('until its address change is applied')
    // Its new address is taken too (saved).
    expect((await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'something-else.dev.example.com', site: 'other' } })).json().available).toBe(false)
  })

  it('hostOwner: saved and live addresses both claim, prefixes still share', () => {
    const rec = { site: echo({ address: { host: 'new.dev.example.com' } }), version: 2, etag: 'e', savedAt: 't', savedBy: 's', applied: { version: 1, at: 't', by: 's', rules: [] } } as SiteRecord
    const live = new Map([['echo', { host: 'old.dev.example.com', pathPrefix: '/app' }]])
    expect(hostOwner('old.dev.example.com', undefined, 'x', [rec], live)).toEqual({ owner: 'echo', sharedWith: [], moving: true })
    expect(hostOwner('old.dev.example.com', '/other', 'x', [rec], live)).toEqual({ owner: undefined, sharedWith: ['echo'] })
    expect(hostOwner('new.dev.example.com', undefined, 'x', [rec], live).owner).toBe('echo')
    expect(hostOwner('old.dev.example.com', undefined, 'echo', [rec], live).owner).toBeUndefined()
  })
})

describe('apply of a moved address', () => {
  it('writes the CR on the new host, audits old → new, and the public lookup follows only once applied', async () => {
    const etag = await live()
    const saved = await saveSite(moved('something-else.dev.example.com'), etag)
    expect(saved.statusCode).toBe(200)
    await settle()
    const saveEvent = h.emit.mock.calls.map((c) => c[0]).find((e) => e.verb === 'update' && e.details?.version === 2)
    expect(saveEvent.details.address).toEqual({ from: { host: 'echo-sandbox.dev.example.com' }, to: { host: 'something-else.dev.example.com' } })
    // Saved, not applied: visitors still meet the old address.
    expect((await publicLoginByHost('echo-sandbox.dev.example.com')).name).toBe('echo')
    await expect(publicLoginByHost('something-else.dev.example.com')).rejects.toMatchObject({ statusCode: 404 })

    const res = await app.inject({ method: 'POST', url: '/sites/echo/apply', headers: W, payload: { version: 2 } })
    expect(res.statusCode).toBe(200)
    expect(cluster.applied.at(-1)!.spec.hosts).toEqual(['something-else.dev.example.com'])
    await settle()
    const moveEvent = h.emit.mock.calls.map((c) => c[0]).find((e) => e.verb === 'address_change')
    expect(moveEvent).toMatchObject({
      targetId: 'echo', result: 'applied',
      details: { version: 2, fromVersion: 1, address: { from: { host: 'echo-sandbox.dev.example.com' }, to: { host: 'something-else.dev.example.com' } } },
    })
    expect(moveEvent.changes.summary).toBe('address https://echo-sandbox.dev.example.com/ → https://something-else.dev.example.com/ (version 2)')
    expect((await publicLoginByHost('something-else.dev.example.com')).name).toBe('echo')
    await expect(publicLoginByHost('echo-sandbox.dev.example.com')).rejects.toMatchObject({ statusCode: 404 })
  })

  it('an overlap during the rewrite refuses the apply (409) and writes no CR', async () => {
    const etag = await live()
    await saveSite(moved('something-else.dev.example.com'), etag)
    const old = (await app.inject({ method: 'GET', url: '/sites/echo' })).json().applied.rules as string[]
    h.gatekit.overlap = (body: unknown) => {
      const b = body as { rules: Array<{ id: string }>; hosts: string[] }
      if (b.hosts.length < 2) return { overlaps: [] }
      const now = b.rules.find((r) => !old.includes(r.id) && gateOfRule('echo', r.id) === 'web')!
      return { overlaps: [{ a: old.find((id) => gateOfRule('echo', id) === 'public')!, b: now.id, method: 'GET', exampleUrl: 'https://x/' }] }
    }
    const before = cluster.applied.length
    const res = await app.inject({ method: 'POST', url: '/sites/echo/apply', headers: W, payload: { version: 2 } })
    expect(res.statusCode).toBe(409)
    expect(cluster.applied.length).toBe(before)
  })
})

describe('movedUrl', () => {
  it('keeps the path, query and fragment, and moves a path under the old prefix to the new one', () => {
    expect(movedUrl('https://a.dev.example.com/x?y=1#z', { host: 'a.dev.example.com' }, { host: 'b.dev.example.com' })).toBe('https://b.dev.example.com/x?y=1#z')
    expect(movedUrl('https://a.dev.example.com/pay/home', { host: 'a.dev.example.com', pathPrefix: '/pay' }, { host: 'a.dev.example.com', pathPrefix: '/payroll' })).toBe('https://a.dev.example.com/payroll/home')
    expect(movedUrl('https://a.dev.example.com/pay', { host: 'a.dev.example.com', pathPrefix: '/pay' }, { host: 'b.dev.example.com' })).toBe('https://b.dev.example.com/')
    expect(movedUrl('https://elsewhere.test/', { host: 'a.dev.example.com' }, { host: 'b.dev.example.com' })).toBeNull()
  })
})
