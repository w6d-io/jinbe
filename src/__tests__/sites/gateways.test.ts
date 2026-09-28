import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { payrollSite } from './fixtures.js'

// Zones on the Envoy Gateway: discovery of the allowed Gateways (listeners, addresses, whether the WAF
// and the IP reputation check are in force), zones created on or moved to a Gateway, the DNS guard
// before a zone drops its Ingress, and host collisions on the Gateway side (routes, listeners).

const h = vi.hoisted(() => ({
  emit: vi.fn(async () => {}),
  dns: {} as Record<string, string[]>,
}))

vi.mock('../../services/redis-client.service.js', () => ({ getRedisClient: () => ({}) }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../middleware/require-admin.js', async () => {
  const { enforcing } = await import('../../policy/declared-routes.js')
  return {
    requireSuperAdmin: enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
      if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden', message: 'needs admin:write' })
    }, 'admin:write'),
    requireSitesApply: enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
      if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden', message: 'needs sites:apply' })
    }, 'sites:apply'),
    requireRecentMfa: async (request: FastifyRequest, reply: FastifyReply) => {
      if (!request.headers['x-test-mfa']) return reply.status(422).send({ error: 'reauth_required', message: 'mfa' })
    },
  }
})

import { sitesRoutes } from '../../sites/routes.js'
import { setKubeGateway, type KubeGateway } from '../../gateway/kube-gateway.js'
import {
  edgePolicyOf, setKubeSites, type EdgePolicy, type GatewayObject, type KubeSites, type ListenerHosts, type RouteHosts, type ZoneCr, type ZoneCrObject,
} from '../../sites/kube-sites.js'
import { protectionOf } from '../../sites/gateways.service.js'
import { routeCollisions } from '../../sites/host-collisions.js'
import { resetSitesConfig } from '../../sites/config.js'
import { setDnsLookup } from '../../sites/dns-probe.js'
import { sitesRepository, type SiteRecord } from '../../sites/repository.js'
import { redisRbacRepository } from '../../services/redis-rbac.repository.js'
import { declaredRoutes, enforcing, guardAll, resetDeclaredRoutes } from '../../policy/declared-routes.js'

const W = { 'x-test-write': '1' }
const WM = { 'x-test-write': '1', 'x-test-mfa': '1' }
const ENVOY = 'adbfc4947b5d64e01a2f27c7aaf66fd5-1321054007.eu-west-3.elb.amazonaws.com'
const NGINX = 'a884b7ca3d5224a749888ee6d89b5d6b-1915485248.eu-west-3.elb.amazonaws.com'
const ok = (type: string) => ({ type, status: 'True', reason: type, message: '', lastTransitionTime: '2026-09-28T10:00:00Z' })

/** Gateway eg as it is on dev-aws-1 (status included). */
const eg = (): GatewayObject => ({
  metadata: { namespace: 'envoy-gateway-system', name: 'eg' },
  spec: {
    gatewayClassName: 'eg',
    listeners: [
      { name: 'http', port: 80, protocol: 'HTTP', allowedRoutes: { namespaces: { from: 'Same' } } },
      { name: 'dev-example-https', hostname: '*.dev.example.com', port: 443, protocol: 'HTTPS', tls: { certificateRefs: [{ name: 'dev-example-tls' }] }, allowedRoutes: { namespaces: { from: 'All' } } },
      { name: 'dev-stairfleet-https', hostname: '*.dev.stairfleet.com', port: 443, protocol: 'HTTPS', tls: { certificateRefs: [{ name: 'dev-stairfleet-tls' }] }, allowedRoutes: { namespaces: { from: 'All' } } },
    ],
  },
  status: {
    addresses: [{ type: 'Hostname', value: ENVOY }],
    conditions: [ok('Accepted'), ok('Programmed')],
    listeners: [{ name: 'http', attachedRoutes: 1, conditions: [ok('Programmed')] }, { name: 'dev-example-https', attachedRoutes: 3, conditions: [ok('Programmed')] }],
  },
})

/** The Gateway-level policies of dev-aws-1, raw as the API returns them. */
const accepted = { ancestors: [{ ancestorRef: { kind: 'Gateway', name: 'eg' }, conditions: [ok('Accepted')] }] }
const livePolicies = (): EdgePolicy[] => [
  edgePolicyOf('SecurityPolicy', {
    metadata: { namespace: 'envoy-gateway-system', name: 'eg-edge' },
    spec: {
      targetRefs: [{ group: 'gateway.networking.k8s.io', kind: 'Gateway', name: 'eg' }],
      authorization: { defaultAction: 'Allow', rules: [{ action: 'Deny', name: 'static-denylist' }] },
      extAuth: { failOpen: true, timeout: '200ms', grpc: { backendRefs: [{ kind: 'Service', name: 'envoy-bouncer', namespace: 'crowdsec', port: 8080 }] } },
    },
    status: accepted,
  }),
  edgePolicyOf('EnvoyExtensionPolicy', {
    metadata: { namespace: 'envoy-gateway-system', name: 'waf-coraza' },
    spec: { targetRefs: [{ kind: 'Gateway', name: 'eg' }], dynamicModule: [{ name: 'composer', filterName: 'coraza-waf', terminalFilter: false }] },
    status: accepted,
  }),
]

const cond = (type: string, status: string, reason: string, message = '') => ({ type, status, reason, message, observedGeneration: 1, lastTransitionTime: '2026-09-28T10:00:00Z' })
const sandboxZone = (): ZoneCrObject => ({
  metadata: { name: 'dev', generation: 1, resourceVersion: '7' },
  spec: { domain: 'dev.example.com', ingress: 'per-site', ingressClass: 'nginx', tls: { mode: 'default' } },
  status: { observedGeneration: 1, conditions: [cond('Ready', 'True', 'Ready')] },
})

const cluster = {
  zones: new Map<string, ZoneCrObject>(),
  created: [] as ZoneCr[],
  updated: [] as ZoneCrObject[],
  gateway: eg() as GatewayObject | null,
  policies: [] as EdgePolicy[],
  routes: [] as RouteHosts[],
  sets: [] as ListenerHosts[],
}

const kube = {
  ping: async () => {}, get: async () => null, apply: async () => {}, delete: async () => {},
  listIngresses: async () => [],
  listZones: async () => [...cluster.zones.values()].map((z) => structuredClone(z)),
  getZone: async (name: string) => (cluster.zones.has(name) ? structuredClone(cluster.zones.get(name)!) : null),
  createZone: async (cr: ZoneCr) => {
    cluster.created.push(structuredClone(cr))
    cluster.zones.set(cr.metadata.name, { metadata: { name: cr.metadata.name, generation: 1 }, spec: cr.spec })
  },
  deleteZone: async () => {},
  updateZone: async (cr: ZoneCrObject) => {
    cluster.updated.push(structuredClone(cr))
    cluster.zones.set(cr.metadata.name, structuredClone(cr))
  },
  getGateway: async (namespace: string, name: string) => (cluster.gateway && namespace === 'envoy-gateway-system' && name === 'eg' ? structuredClone(cluster.gateway) : null),
  listEdgePolicies: async () => structuredClone(cluster.policies),
  listHTTPRoutes: async () => structuredClone(cluster.routes),
  listListenerSets: async () => structuredClone(cluster.sets),
} satisfies KubeSites

const record = (name: string, host: string): SiteRecord => ({
  site: payrollSite({ name, address: { host } }), version: 1, etag: 'e', savedAt: 't', savedBy: 'sam',
  applied: { version: 1, at: 't', by: 'sam', rules: [] },
})
let records: SiteRecord[] = []
let app: FastifyInstance

beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request) => {
    request.userContext = { id: 'sam-id', email: 'sam@x.test', name: 'Sam' }
  })
  await app.register(sitesRoutes, { prefix: '/sites' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  h.emit.mockClear()
  h.dns = { [ENVOY]: ['15.236.101.5', '35.180.216.63'], [NGINX]: ['51.44.199.227', '15.237.7.87'] }
  cluster.zones = new Map([['dev', sandboxZone()]])
  cluster.created = []
  cluster.updated = []
  cluster.gateway = eg()
  cluster.policies = livePolicies()
  cluster.routes = []
  cluster.sets = []
  records = []
  process.env.SITES_NAMESPACE = 'auth-dev'
  process.env.SITES_KUBE = 'in-cluster'
  process.env.SITES_ZONES = '[]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.example.com'
  process.env.SITES_ZONE_ALLOWED_PARENTS = 'dev.example.com,dev.stairfleet.com'
  process.env.SITES_ZONE_ISSUERS = 'letsencrypt-prod'
  process.env.SITES_GATEWAYS = 'envoy-gateway-system/eg'
  process.env.SITES_RESERVED_HOSTS = ''
  resetSitesConfig()
  setKubeSites(kube)
  setKubeGateway({ get: async () => null, liveOathkeeperConfig: async () => null } as unknown as KubeGateway)
  setDnsLookup({ addresses: async (name) => h.dns[name] ?? [] })
  vi.spyOn(sitesRepository, 'list').mockImplementation(async () => records)
  vi.spyOn(redisRbacRepository, 'getAccessRules').mockResolvedValue([])
})

const zoneEvents = () => h.emit.mock.calls.map((c) => (c as unknown as [{ v1Event?: string; targetId?: string; details?: unknown }])[0]).filter((e) => e.v1Event?.startsWith('zone.'))
const patch = (payload: unknown, headers = WM) => app.inject({ method: 'PATCH', url: '/sites/zones/dev', headers, payload })

describe('protection', () => {
  it('the live eg policies: WAF (Coraza) and IP reputation (CrowdSec ext_authz) on the whole Gateway', () => {
    expect(protectionOf('eg', livePolicies())).toEqual({
      waf: { policy: 'envoy-gateway-system/waf-coraza', modules: ['composer', 'coraza-waf'], accepted: true },
      ipReputation: { policy: 'envoy-gateway-system/eg-edge', backend: 'crowdsec/envoy-bouncer', failOpen: true, accepted: true },
      denylist: { policy: 'envoy-gateway-system/eg-edge' },
      protected: true,
      summary: 'Every route is inspected by the WAF (composer, coraza-waf) and checked against IP bans (crowdsec/envoy-bouncer, fail-open)',
    })
  })

  it('is not claimed without the WAF, when EG has not accepted a policy, or for a policy on one listener or route', () => {
    const [edge, waf] = livePolicies()
    expect(protectionOf('eg', [edge])).toMatchObject({ protected: false, summary: 'Not protected: no WAF policy' })
    expect(protectionOf('eg', [edge, { ...waf, accepted: null }])).toMatchObject({ protected: false, summary: 'Not protected: WAF policy waf-coraza not accepted' })
    expect(protectionOf('eg', [edge, { ...waf, targets: [{ kind: 'Gateway', name: 'eg', sectionName: 'dev-example-https' }] }]).protected).toBe(false)
    expect(protectionOf('eg', [{ ...edge, targets: [{ kind: 'HTTPRoute', name: 'grafana' }] }, waf]).protected).toBe(false)
    expect(protectionOf('eg', [edge, { ...waf, modules: ['lua-hello'] }]).protected).toBe(false)
    expect(protectionOf('other', livePolicies()).protected).toBe(false)
  })
})

describe('GET /gateways', () => {
  it('the allowed Gateways with listeners, addresses and protection', async () => {
    const res = await app.inject({ method: 'GET', url: '/sites/gateways' })
    expect(res.statusCode).toBe(200)
    const [g] = res.json().gateways
    expect(g).toMatchObject({ key: 'envoy-gateway-system/eg', exists: true, className: 'eg', addresses: [ENVOY], programmed: true, protection: { protected: true } })
    expect(g.listeners[1]).toEqual({ name: 'dev-example-https', hostname: '*.dev.example.com', port: 443, protocol: 'HTTPS', tls: true, routesFromAll: true, programmed: true, attachedRoutes: 3 })
    expect(g.listeners[2]).toMatchObject({ name: 'dev-stairfleet-https', programmed: null, attachedRoutes: null })
  })

  it('a missing Gateway says so; none configured = none offered, nothing read', async () => {
    cluster.gateway = null
    expect((await app.inject({ method: 'GET', url: '/sites/gateways' })).json().gateways[0]).toMatchObject({ exists: false, protection: { protected: false } })
    process.env.SITES_GATEWAYS = ''
    resetSitesConfig()
    expect((await app.inject({ method: 'GET', url: '/sites/gateways' })).json()).toEqual({ gateways: [] })
  })

  it('reads need admin:read only; PATCH /zones/:name is gated like create', async () => {
    resetDeclaredRoutes()
    const admin = Fastify()
    await admin.register(async (scope) => {
      guardAll(scope, enforcing(async () => {}, 'admin:read'), () => false)
      await scope.register(sitesRoutes, { prefix: '/sites' })
    }, { prefix: '/api/admin' })
    await admin.ready()
    const find = (method: string, path: string) => declaredRoutes().find((r) => r.method === method && r.path === path)?.permission
    expect(find('GET', '/api/admin/sites/gateways')).toBe('admin:read')
    expect(find('PATCH', '/api/admin/sites/zones/:name')).toBe('sites:apply')
    await admin.close()
    expect((await patch({ ingress: 'none' }, {})).statusCode).toBe(403)
    expect((await patch({ ingress: 'none' }, W)).statusCode).toBe(422)
    expect(cluster.updated).toEqual([])
  })
})

describe('zones on a Gateway', () => {
  it('create: gateway only (ingress none), behind the WAF; DNS is probed against the Gateway', async () => {
    const res = await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'dev.stairfleet.com', ingress: 'none', gateway: { namespace: 'envoy-gateway-system', name: 'eg' } } })
    expect(res.statusCode).toBe(201)
    expect(cluster.created[0].spec).toEqual({ domain: 'dev.stairfleet.com', ingress: 'none', tls: { mode: 'default' }, gateway: { namespace: 'envoy-gateway-system', name: 'eg' } })
    expect(res.json()).toMatchObject({ gateway: { name: 'eg' }, exposure: { entry: 'gateway', wafBypass: false, protected: true }, protection: { protected: true }, dns: { expected: ['15.236.101.5', '35.180.216.63'] } })
    expect(zoneEvents()).toEqual([expect.objectContaining({ v1Event: 'zone.created', details: expect.objectContaining({ ingress: 'none', gateway: 'envoy-gateway-system/eg' }) })])
  })

  it('create: refused for a Gateway not in SITES_GATEWAYS, a missing one, or no listener for the zone with TLS default', async () => {
    const post = (payload: unknown) => app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload })
    expect((await post({ domain: 'a.dev.example.com', gateway: { namespace: 'envoy-gateway-system', name: 'internal' } })).json().error).toBe('gateway_not_allowed')
    cluster.gateway = null
    expect((await post({ domain: 'a.dev.example.com', gateway: { namespace: 'envoy-gateway-system', name: 'eg' } })).json().error).toBe('gateway_not_found')
    cluster.gateway = eg()
    const nested = await post({ domain: 'authdev.dev.example.com', ingress: 'none', gateway: { namespace: 'envoy-gateway-system', name: 'eg' } })
    expect(nested.json()).toMatchObject({ error: 'listener_not_covering', message: expect.stringContaining('no HTTPS listener for *.authdev.dev.example.com') })
    // its own listener (ListenerSet) with an issued certificate is fine
    expect((await post({ domain: 'authdev.dev.example.com', ingress: 'none', tls: { mode: 'issuer' }, gateway: { namespace: 'envoy-gateway-system', name: 'eg' } })).statusCode).toBe(201)
    expect((await post({ domain: 'b.dev.example.com', ingress: 'none' })).statusCode).toBe(400)
    expect(cluster.created).toHaveLength(1)
  })

  it('the migration: attach the gateway (both entry points), then ingress none once DNS reaches Envoy', async () => {
    records = [record('echo', 'echo-sandbox-tes.dev.example.com'), record('stairfleet1', 'stairfleet1.dev.example.com')]
    h.dns['echo-sandbox-tes.dev.example.com'] = ['51.44.199.227']
    h.dns['stairfleet1.dev.example.com'] = ['51.44.199.227']

    // 1. attach: the Ingresses stay, the WAF can still be bypassed through nginx
    const attach = await patch({ gateway: { namespace: 'envoy-gateway-system', name: 'eg' } })
    expect(attach.statusCode).toBe(200)
    expect(cluster.updated.at(-1)).toMatchObject({ metadata: { name: 'dev', resourceVersion: '7' }, spec: { domain: 'dev.example.com', ingress: 'per-site', gateway: { name: 'eg' } } })
    expect(attach.json()).toMatchObject({ exposure: { entry: 'both', wafBypass: true, protected: false }, checks: [] })

    // 3. ingress none while DNS still points at nginx: refused, per host
    const early = await patch({ ingress: 'none' })
    expect(early.statusCode).toBe(409)
    expect(early.json()).toMatchObject({ error: 'dns_not_on_gateway' })
    expect(early.json().checks).toEqual([
      { level: 'error', code: 'dns_elsewhere', host: 'echo-sandbox-tes.dev.example.com', addresses: ['51.44.199.227'], message: expect.stringContaining('not to Gateway envoy-gateway-system/eg') },
      { level: 'error', code: 'dns_elsewhere', host: 'stairfleet1.dev.example.com', addresses: ['51.44.199.227'], message: expect.any(String) },
    ])
    expect(cluster.updated).toHaveLength(1)

    // DNS moved (one host) + confirm for the other, or all moved: accepted
    h.dns['echo-sandbox-tes.dev.example.com'] = ['15.236.101.5']
    expect((await patch({ ingress: 'none' })).statusCode).toBe(409)
    h.dns['stairfleet1.dev.example.com'] = ['35.180.216.63']
    const done = await patch({ ingress: 'none' })
    expect(done.statusCode).toBe(200)
    expect(cluster.updated.at(-1)!.spec).toMatchObject({ ingress: 'none', gateway: { name: 'eg' } })
    expect(done.json()).toMatchObject({ exposure: { entry: 'gateway', wafBypass: false, protected: true } })
    expect(done.json().checks.map((c: { code: string }) => c.code)).toEqual(['dns_ok', 'dns_ok'])
    expect(zoneEvents().map((e) => e.v1Event)).toEqual(['zone.updated', 'zone.updated'])
    expect(zoneEvents()[1]).toMatchObject({ details: expect.objectContaining({ ingress: 'none', gateway: 'envoy-gateway-system/eg', from: 'ingress per-site, gateway envoy-gateway-system/eg' }) })

    // rollback: the Ingress back first (the gateway cannot go while it is the only entry point)
    expect((await patch({ gateway: null })).json().error).toBe('no_entry_point')
    expect((await patch({ ingress: 'per-site' })).statusCode).toBe(200)
    expect((await patch({ gateway: null })).statusCode).toBe(200)
    expect(cluster.updated.at(-1)!.spec).toEqual({ domain: 'dev.example.com', ingress: 'per-site', ingressClass: 'nginx', tls: { mode: 'default' } })
  })

  it('confirm drops the Ingress despite DNS; an unprotected Gateway is a warning', async () => {
    records = [record('echo', 'echo-sandbox-tes.dev.example.com')]
    h.dns['echo-sandbox-tes.dev.example.com'] = ['51.44.199.227']
    cluster.policies = [livePolicies()[0]]
    const res = await patch({ ingress: 'none', gateway: { namespace: 'envoy-gateway-system', name: 'eg' }, confirm: true })
    expect(res.statusCode).toBe(200)
    expect(res.json().checks[0]).toEqual({ level: 'warn', code: 'gateway_not_protected', message: 'Gateway envoy-gateway-system/eg: Not protected: no WAF policy' })
    expect(res.json().exposure).toEqual({ entry: 'gateway', wafBypass: false, protected: false })
  })

  it('GET /zones/:name shows the gateway, its GatewayReady condition and protection', async () => {
    cluster.zones.set('dev', { ...sandboxZone(), spec: { ...sandboxZone().spec, ingress: 'none', gateway: { namespace: 'envoy-gateway-system', name: 'eg' } },
      status: { observedGeneration: 1, conditions: [cond('GatewayReady', 'True', 'Programmed', `gateway envoy-gateway-system/eg at ${ENVOY}, listener dev-example-https (*.dev.example.com)`), cond('Ready', 'True', 'Ready')] } })
    const out = (await app.inject({ method: 'GET', url: '/sites/zones/dev' })).json()
    expect(out).toMatchObject({ ingress: 'none', exposure: { entry: 'gateway', protected: true }, status: { gateway: { status: 'True', reason: 'Programmed' } }, protection: { waf: { accepted: true } } })
    const list = (await app.inject({ method: 'GET', url: '/sites/zones' })).json()
    expect(list).toContainEqual(expect.objectContaining({ suffix: 'dev.example.com', ingress: 'none', gateway: 'envoy-gateway-system/eg', ready: true }))
  })
})

describe('host collisions on the Gateway side', () => {
  const objects = (routes: RouteHosts[], sets: ListenerHosts[] = []) => ({
    routes,
    listeners: [{ kind: 'Gateway' as const, namespace: 'envoy-gateway-system', name: 'eg', gateway: 'envoy-gateway-system/eg', listeners: [{ name: 'dev-example-https', hostname: '*.dev.example.com' }] }, ...sets],
  })
  const route = (namespace: string, name: string, hostnames: string[], labels: Record<string, string> = {}, annotations: Record<string, string> = {}): RouteHosts => ({ namespace, name, hostnames, labels, annotations })

  it('a foreign route naming the host takes it; the operator\'s host route for it is the site\'s own; a wildcard route shadows', () => {
    const gw = 'envoy-gateway-system/eg'
    expect(routeCollisions('grafana.dev.example.com', gw, objects([route('monitoring', 'grafana', ['grafana.dev.example.com'])]))).toEqual([
      { level: 'error', code: 'host_taken', message: 'HTTPRoute monitoring/grafana serves grafana.dev.example.com; no route would be created for this host', path: 'address.host' },
    ])
    const own = route('auth-dev', 'host-b1374612', ['echo.dev.example.com'], { 'app.kubernetes.io/managed-by': 'site-operator', 'auth.w6d.io/host-route': 'true' }, { 'auth.w6d.io/host': 'echo.dev.example.com' })
    expect(routeCollisions('echo.dev.example.com', gw, objects([own]))).toEqual([])
    expect(routeCollisions('echo.dev.example.com', gw, objects([route('legacy', 'wild', ['*.dev.example.com'])]))).toEqual([
      { level: 'warn', code: 'host_shadows_wildcard', message: 'HTTPRoute legacy/wild serves *.dev.example.com; the gateway routes echo.dev.example.com to this Site', path: 'address.host' },
    ])
    // nothing when the host's zone has no gateway, or the Gateway API is not read
    expect(routeCollisions('grafana.dev.example.com', undefined, objects([route('monitoring', 'grafana', ['grafana.dev.example.com'])]))).toEqual([])
    expect(routeCollisions('grafana.dev.example.com', gw, null)).toEqual([])
  })

  it('an exact-hostname listener on the zone\'s Gateway takes the host (superadmin.dev\'s ListenerSet); one on another Gateway does not', () => {
    const set = (gateway: string): ListenerHosts => ({ kind: 'ListenerSet', namespace: 'example', name: 'superadmin-shell', gateway, listeners: [{ name: 'https', hostname: 'superadmin.dev.example.com' }] })
    expect(routeCollisions('superadmin.dev.example.com', 'envoy-gateway-system/eg', objects([], [set('envoy-gateway-system/eg')]))).toEqual([{
      level: 'error', code: 'host_taken', path: 'address.host',
      message: 'ListenerSet example/superadmin-shell (listener https) serves superadmin.dev.example.com (exact hostname: it wins over the zone\'s listener)',
    }])
    expect(routeCollisions('superadmin.dev.example.com', 'envoy-gateway-system/eg', objects([], [set('envoy-gateway-system/internal')]))).toEqual([])
  })

  it('check-host reports them for a host under a zone with a gateway', async () => {
    cluster.zones.set('dev', { ...sandboxZone(), spec: { ...sandboxZone().spec, gateway: { namespace: 'envoy-gateway-system', name: 'eg' } } })
    cluster.routes = [route('monitoring', 'grafana', ['grafana.dev.example.com'])]
    const out = (await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'grafana.dev.example.com' } })).json()
    expect(out.available).toBe(false)
    expect(out.checks).toContainEqual({ level: 'error', code: 'host_taken', message: 'HTTPRoute monitoring/grafana serves grafana.dev.example.com; no route would be created for this host' })
    // the same host in a zone without a gateway: the Gateway side is not the operator's concern
    cluster.zones.set('dev', sandboxZone())
    expect((await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'grafana.dev.example.com' } })).json().available).toBe(true)
  })
})
