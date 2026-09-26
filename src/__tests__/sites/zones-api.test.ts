import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import { payrollSite } from './fixtures.js'

// Z-2: zones from kuma. Reads under admin:read; create and delete change what the platform serves,
// so they need sites:apply and a recent second factor, like an apply. A create outside the allowed
// parents is refused; a delete is refused while a saved site stands on the zone. DNS is only reported.

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
import { setKubeSites, KubeRefused, KubeUnavailable, type IngressHosts, type KubeSites, type ZoneCr, type ZoneCrObject } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import { setDnsLookup } from '../../sites/dns-probe.js'
import { sitesRepository, type SiteRecord } from '../../sites/repository.js'
import { redisRbacRepository } from '../../services/redis-rbac.repository.js'
import { declaredRoutes, enforcing, guardAll, resetDeclaredRoutes } from '../../policy/declared-routes.js'

const W = { 'x-test-write': '1' }
const WM = { 'x-test-write': '1', 'x-test-mfa': '1' }

const cond = (type: string, status: string, reason: string, message = '') => ({ type, status, reason, message, observedGeneration: 1, lastTransitionTime: '2026-09-26T10:00:00Z' })

const devZone = (): ZoneCrObject => ({
  metadata: { name: 'dev', generation: 1, creationTimestamp: '2026-09-01T00:00:00Z' },
  spec: { domain: 'dev.stairling.com', tls: { mode: 'issuer', issuer: 'letsencrypt-dns' } },
  status: {
    observedGeneration: 1,
    conditions: [
      cond('Validated', 'True', 'Valid'),
      cond('IngressReady', 'True', 'Admitted', 'load balancer lb.example.net'),
      cond('CertificateReady', 'False', 'Pending', 'waiting for DNS-01'),
      cond('Ready', 'False', 'Pending', 'CertificateReady: waiting for DNS-01'),
    ],
  },
})

const cluster = {
  zones: new Map<string, ZoneCrObject>(),
  created: [] as ZoneCr[],
  deleted: [] as string[],
  up: true,
  refuse: null as KubeRefused | null,
  ingresses: [] as IngressHosts[],
}

const ing = (namespace: string, name: string, hosts: string[], labels: Record<string, string> = {}, paths: string[] = ['/']): IngressHosts =>
  ({ namespace, name, hosts, labels, paths: Object.fromEntries(hosts.map((h) => [h, paths])) })
const OP = { 'app.kubernetes.io/managed-by': 'site-operator' }

const kube = {
  ping: async () => {}, get: async () => null, apply: async () => {}, delete: async () => {},
  listIngresses: async () => {
    if (!cluster.up) throw new KubeUnavailable('down')
    return structuredClone(cluster.ingresses)
  },
  listZones: async () => {
    if (!cluster.up) throw new KubeUnavailable('down')
    return [...cluster.zones.values()].map((z) => structuredClone(z))
  },
  getZone: async (name: string) => {
    if (!cluster.up) throw new KubeUnavailable('down')
    return cluster.zones.has(name) ? structuredClone(cluster.zones.get(name)!) : null
  },
  createZone: async (cr: ZoneCr) => {
    if (!cluster.up) throw new KubeUnavailable('down')
    if (cluster.refuse) throw cluster.refuse
    cluster.created.push(structuredClone(cr))
    cluster.zones.set(cr.metadata.name, { metadata: { name: cr.metadata.name, generation: 1 }, spec: cr.spec })
  },
  deleteZone: async (name: string) => {
    cluster.deleted.push(name)
    cluster.zones.delete(name)
  },
} satisfies KubeSites

const record = (name: string, host: string, applied = true): SiteRecord => ({
  site: payrollSite({ name, address: { host } }), version: 1, etag: 'e', savedAt: 't', savedBy: 'sam',
  ...(applied ? { applied: { version: 1, at: 't', by: 'sam', rules: [] } } : {}),
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
  h.dns = { 'lb.example.net': ['203.0.113.10'] }
  cluster.zones = new Map([['dev', devZone()]])
  cluster.created = []
  cluster.deleted = []
  cluster.up = true
  cluster.refuse = null
  // The operator's own Ingresses: the dev zone wildcard, and payroll's vanity Ingress.
  cluster.ingresses = [
    ing('auth', 'zone-dev', ['*.dev.stairling.com'], { ...OP, 'auth.w6d.io/zone': 'dev' }),
    ing('auth', 'site-payroll', ['payroll.dev.stairling.com'], { ...OP, 'auth.w6d.io/site': 'payroll' }),
  ]
  process.env.SITES_NAMESPACE = 'auth'
  records = []
  process.env.SITES_KUBE = 'in-cluster'
  process.env.SITES_ZONES = '[{"suffix":"stairfleet.com","cookieDomain":".stairfleet.com"}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.stairling.com'
  process.env.SITES_ZONE_ALLOWED_PARENTS = 'dev.stairling.com,stairfleet.com'
  process.env.SITES_ZONE_ISSUERS = 'letsencrypt-dns,letsencrypt-staging'
  delete process.env.SITES_INGRESS_ADDRESSES
  process.env.SITES_RESERVED_HOSTS = ''
  resetSitesConfig()
  setKubeSites(kube)
  // Any name under a domain with a wildcard entry answers like the wildcard.
  setDnsLookup({
    addresses: async (name) => h.dns[name] ?? Object.entries(h.dns).find(([k]) => k.startsWith('*.') && name.endsWith(k.slice(1)))?.[1] ?? [],
  })
  vi.spyOn(sitesRepository, 'list').mockImplementation(async () => records)
  vi.spyOn(redisRbacRepository, 'getAccessRules').mockResolvedValue([])
})

const zoneEvents = () => h.emit.mock.calls.map((c) => (c as unknown as [{ v1Event?: string; targetId?: string; details?: unknown }])[0]).filter((e) => e.v1Event?.startsWith('zone.'))

describe('guards', () => {
  it('publishes its route rows: reads admin:read, create/delete sites:apply', async () => {
    resetDeclaredRoutes()
    const admin = Fastify()
    await admin.register(async (scope) => {
      guardAll(scope, enforcing(async () => {}, 'admin:read'), () => false)
      await scope.register(sitesRoutes, { prefix: '/sites' })
    }, { prefix: '/api/admin' })
    await admin.ready()
    const find = (method: string, path: string) => declaredRoutes().find((r) => r.method === method && r.path === path)?.permission
    expect(find('GET', '/api/admin/sites/zones/:name')).toBe('admin:read')
    expect(find('POST', '/api/admin/sites/zones/suggest')).toBe('admin:read')
    expect(find('POST', '/api/admin/sites/zones')).toBe('sites:apply')
    expect(find('DELETE', '/api/admin/sites/zones/:name')).toBe('sites:apply')
    await admin.close()
  })

  it('create and delete need sites:apply, then a recent second factor; nothing reaches the cluster otherwise', async () => {
    expect((await app.inject({ method: 'POST', url: '/sites/zones', payload: { domain: 'apps.stairfleet.com' } })).statusCode).toBe(403)
    expect((await app.inject({ method: 'POST', url: '/sites/zones', headers: W, payload: { domain: 'apps.stairfleet.com' } })).statusCode).toBe(422)
    expect((await app.inject({ method: 'DELETE', url: '/sites/zones/dev', headers: W })).statusCode).toBe(422)
    expect(cluster.created).toEqual([])
    expect(cluster.deleted).toEqual([])
    expect(zoneEvents()).toEqual([])
  })
})

describe('GET /zones/:name', () => {
  it('spec, operator conditions and the sites the zone serves', async () => {
    records = [record('payroll', 'payroll.dev.stairling.com'), record('shop', 'shop.stairfleet.com', false)]
    const res = await app.inject({ method: 'GET', url: '/sites/zones/dev' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({
      name: 'dev',
      domain: 'dev.stairling.com',
      wildcard: '*.dev.stairling.com',
      ingress: 'wildcard',
      ingressClass: null,
      tls: { mode: 'issuer', issuer: 'letsencrypt-dns' },
      cookieDomain: '.dev.stairling.com',
      sso: true,
      createdAt: '2026-09-01T00:00:00Z',
      status: {
        observed: true,
        ready: false,
        ingress: { status: 'True', reason: 'Admitted', message: 'load balancer lb.example.net', since: '2026-09-26T10:00:00Z' },
        certificate: { status: 'False', reason: 'Pending', message: 'waiting for DNS-01', since: '2026-09-26T10:00:00Z' },
        validated: { status: 'True', reason: 'Valid', message: '', since: '2026-09-26T10:00:00Z' },
        domainTaken: false,
        message: 'CertificateReady: waiting for DNS-01',
      },
      sites: [{ name: 'payroll', host: 'payroll.dev.stairling.com', applied: true }],
    })
  })

  it('says when the domain already belongs to an older zone', async () => {
    cluster.zones.set('dev-copy', {
      metadata: { name: 'dev-copy', generation: 1 },
      spec: { domain: 'dev.stairling.com' },
      status: { observedGeneration: 1, conditions: [cond('Validated', 'False', 'DomainTaken', 'domain dev.stairling.com already belongs to zone dev')] },
    })
    const out = (await app.inject({ method: 'GET', url: '/sites/zones/dev-copy' })).json()
    expect(out.status).toMatchObject({ observed: true, ready: false, domainTaken: true })
  })

  it('a zone the operator has not reconciled yet is not ready, and says so', async () => {
    cluster.zones.set('new', { metadata: { name: 'new', generation: 1 }, spec: { domain: 'new.stairfleet.com' } })
    expect((await app.inject({ method: 'GET', url: '/sites/zones/new' })).json().status).toMatchObject({ observed: false, ready: false, message: 'waiting for the operator' })
  })

  it('404 for an unknown zone, 400 for a name that cannot be one, 503 when the cluster cannot answer', async () => {
    expect((await app.inject({ method: 'GET', url: '/sites/zones/nope' })).statusCode).toBe(404)
    expect((await app.inject({ method: 'GET', url: '/sites/zones/Not_A_Name' })).statusCode).toBe(400)
    cluster.up = false
    expect((await app.inject({ method: 'GET', url: '/sites/zones/dev' })).statusCode).toBe(503)
  })
})

describe('POST /zones', () => {
  it('creates the Zone CR (spec only, managed-by jinbe), audits zone.created, reports DNS', async () => {
    h.dns['*.apps.stairfleet.com'] = ['203.0.113.10']
    const res = await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'Apps.Stairfleet.com', tls: { mode: 'issuer', issuer: 'letsencrypt-dns' } } })
    expect(res.statusCode).toBe(201)
    expect(cluster.created).toEqual([{
      apiVersion: 'auth.w6d.io/v1alpha1',
      kind: 'Zone',
      metadata: { name: 'apps-stairfleet-com', labels: { 'app.kubernetes.io/managed-by': 'jinbe' } },
      spec: { domain: 'apps.stairfleet.com', ingress: 'wildcard', tls: { mode: 'issuer', issuer: 'letsencrypt-dns' } },
    }])
    expect(res.json()).toMatchObject({
      name: 'apps-stairfleet-com', domain: 'apps.stairfleet.com', cookieDomain: '.stairfleet.com', sso: true,
      status: { observed: false, ready: false }, sites: [],
      dns: { status: 'ok', expected: ['203.0.113.10'] },
      checks: [],
    })
    expect(zoneEvents()).toEqual([expect.objectContaining({
      v1Event: 'zone.created', targetId: 'apps-stairfleet-com',
      details: { domain: 'apps.stairfleet.com', ingress: 'wildcard', tls: 'issuer', issuer: 'letsencrypt-dns' },
    })])
  })

  it('a domain outside SITES_ZONE_ALLOWED_PARENTS is refused before the cluster is asked', async () => {
    const res = await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'evil.example.com' } })
    expect(res.statusCode).toBe(422)
    expect(res.json().error).toBe('zone_not_allowed')
    // A look-alike suffix is not "under" the parent.
    expect((await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'notstairfleet.com' } })).json().error).toBe('zone_not_allowed')
    process.env.SITES_ZONE_ALLOWED_PARENTS = ''
    resetSitesConfig()
    expect((await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'apps.stairfleet.com' } })).json().error).toBe('zone_not_allowed')
    expect(cluster.created).toEqual([])
    expect(zoneEvents()).toEqual([])
  })

  it('TLS: a named issuer must be offered; secret needs secretName; stray fields are refused', async () => {
    const post = (payload: unknown) => app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload })
    expect((await post({ domain: 'a.stairfleet.com', tls: { mode: 'issuer', issuer: 'self-signed' } })).json().error).toBe('issuer_not_allowed')
    expect((await post({ domain: 'a.stairfleet.com', tls: { mode: 'secret' } })).statusCode).toBe(400)
    expect((await post({ domain: 'a.stairfleet.com', tls: { mode: 'default', issuer: 'letsencrypt-dns' } })).statusCode).toBe(400)
    expect((await post({ domain: 'a.stairfleet.com', cookieDomain: '.x' })).statusCode).toBe(400)
    expect((await post({ domain: 'not a domain' })).statusCode).toBe(400)
    expect(cluster.created).toEqual([])
  })

  it('409 when the domain is already a zone, or the cluster already has the name', async () => {
    const dup = await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'dev.stairling.com', ingress: 'per-site' } })
    expect(dup.statusCode).toBe(409)
    expect(dup.json()).toMatchObject({ error: 'zone_exists', message: expect.stringContaining('zone dev') })
    cluster.refuse = new KubeRefused(409, 'zone_exists', 'A Zone named x already exists')
    expect((await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'x.stairfleet.com' } })).statusCode).toBe(409)
    cluster.refuse = new KubeRefused(422, 'zone_rejected', 'The cluster refused the Zone: ingress class x is not allowed')
    expect((await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'x.stairfleet.com' } })).json().error).toBe('zone_rejected')
    expect(zoneEvents()).toEqual([])
  })

  it('503 and nothing audited when the cluster cannot answer', async () => {
    cluster.up = false
    expect((await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'apps.stairfleet.com' } })).statusCode).toBe(503)
    expect(zoneEvents()).toEqual([])
  })
})

describe('DELETE /zones/:name', () => {
  it('is refused with the sites listed while a saved site has a host under it', async () => {
    records = [record('payroll', 'payroll.dev.stairling.com'), record('draft-ish', 'wiki.dev.stairling.com', false)]
    const res = await app.inject({ method: 'DELETE', url: '/sites/zones/dev', headers: WM })
    expect(res.statusCode).toBe(409)
    expect(res.json()).toMatchObject({
      error: 'zone_in_use',
      sites: [{ name: 'draft-ish', host: 'wiki.dev.stairling.com', applied: false }, { name: 'payroll', host: 'payroll.dev.stairling.com', applied: true }],
    })
    expect(cluster.deleted).toEqual([])
    expect(zoneEvents()).toEqual([])
  })

  it('a site served by a more specific zone does not hold the parent zone', async () => {
    cluster.zones.set('apps', { metadata: { name: 'apps' }, spec: { domain: 'apps.dev.stairling.com' } })
    records = [record('shop', 'shop.apps.dev.stairling.com')]
    expect((await app.inject({ method: 'DELETE', url: '/sites/zones/dev', headers: WM })).statusCode).toBe(200)
    expect((await app.inject({ method: 'DELETE', url: '/sites/zones/apps', headers: WM })).statusCode).toBe(409)
  })

  it('a duplicate zone (DomainTaken) can go even though sites use the domain', async () => {
    cluster.zones.set('dev-copy', { metadata: { name: 'dev-copy' }, spec: { domain: 'dev.stairling.com' } })
    records = [record('payroll', 'payroll.dev.stairling.com')]
    expect((await app.inject({ method: 'DELETE', url: '/sites/zones/dev-copy', headers: WM })).statusCode).toBe(200)
  })

  it('deletes an unused zone and audits zone.deleted; 404 for an unknown one', async () => {
    const res = await app.inject({ method: 'DELETE', url: '/sites/zones/dev', headers: WM })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ name: 'dev', domain: 'dev.stairling.com', deleted: true })
    expect(cluster.deleted).toEqual(['dev'])
    expect(zoneEvents()).toEqual([expect.objectContaining({ v1Event: 'zone.deleted', targetId: 'dev', details: { domain: 'dev.stairling.com', ingress: 'wildcard', tls: 'issuer' } })])
    expect((await app.inject({ method: 'DELETE', url: '/sites/zones/dev', headers: WM })).statusCode).toBe(404)
  })
})

describe('POST /zones/suggest', () => {
  const suggest = (host: string) => app.inject({ method: 'POST', url: '/sites/zones/suggest', payload: { host } })

  it('a host a zone already covers needs nothing', async () => {
    expect((await suggest('payroll.dev.stairling.com')).json()).toEqual({ host: 'payroll.dev.stairling.com', covered: true, zone: 'dev.stairling.com' })
  })

  it('outside every zone: the parent domain, TLS choices, SSO, and the wildcard DNS checked against the platform ingress', async () => {
    h.dns['*.apps.stairfleet.com'] = ['203.0.113.10']
    const out = (await suggest('shop.apps.stairfleet.com')).json()
    expect(out).toMatchObject({
      host: 'shop.apps.stairfleet.com',
      covered: false,
      domain: 'apps.stairfleet.com',
      name: 'apps-stairfleet-com',
      wildcard: '*.apps.stairfleet.com',
      allowed: true,
      allowedParents: ['dev.stairling.com', 'stairfleet.com'],
      dns: { status: 'ok', addresses: ['203.0.113.10'], expected: ['203.0.113.10'] },
      tls: { modes: ['default', 'issuer', 'secret'], issuers: ['letsencrypt-dns', 'letsencrypt-staging'], suggested: 'issuer' },
      ingress: { modes: ['wildcard', 'per-site'], suggested: 'wildcard', shared: [] },
      // The cookie configured for stairfleet.com reaches every zone under it.
      cookieDomain: '.stairfleet.com',
      sso: true,
      checks: [],
    })
    expect(out.dns.probe).toMatch(/^jinbe-probe-[0-9a-f]{8}\.apps\.stairfleet\.com$/)
  })

  it('DNS is reported, not enforced: unresolved, elsewhere, or unverifiable', async () => {
    const dnsOf = async (host: string) => (await suggest(host)).json()
    expect((await dnsOf('shop.b2b.stairfleet.com')).dns.status).toBe('unresolved')
    h.dns['*.b2b.stairfleet.com'] = ['198.51.100.7']
    const elsewhere = await dnsOf('shop.b2b.stairfleet.com')
    expect(elsewhere).toMatchObject({ allowed: true, dns: { status: 'elsewhere' } })
    expect(elsewhere.checks).toContainEqual(expect.objectContaining({ level: 'warn', code: 'dns_elsewhere' }))
    // No configured ingress and no admitted zone to learn it from.
    cluster.zones.clear()
    expect((await dnsOf('shop.b2b.stairfleet.com')).dns.status).toBe('unverified')
    // Configured addresses win over what the zones say.
    process.env.SITES_INGRESS_ADDRESSES = '198.51.100.7'
    resetSitesConfig()
    expect((await dnsOf('shop.b2b.stairfleet.com')).dns.status).toBe('ok')
  })

  it('a parent outside the allow-list is not allowed and not probed', async () => {
    const out = (await suggest('www.example.com')).json()
    expect(out).toMatchObject({ covered: false, domain: 'example.com', allowed: false, dns: null, sso: false })
    expect(out.checks).toEqual([
      expect.objectContaining({ level: 'error', code: 'zone_not_allowed' }),
      expect.objectContaining({ level: 'warn', code: 'no_sso' }),
    ])
  })
})

describe('check-host and preview offer the zone to create', () => {
  it('check-host outside every zone carries suggestedZone; inside a zone it does not', async () => {
    const out = (await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'shop.apps.stairfleet.com' } })).json()
    expect(out).toMatchObject({ available: false, zone: null, suggestedZone: { covered: false, domain: 'apps.stairfleet.com', allowed: true } })
    const inside = (await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'new.dev.stairling.com' } })).json()
    expect(inside.suggestedZone).toBeUndefined()
  })

  it('a host too deep for its zone is offered the zone one label under it', async () => {
    const out = (await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'shop.apps.dev.stairling.com' } })).json()
    expect(out.suggestedZone).toMatchObject({ domain: 'apps.dev.stairling.com', allowed: true, sso: true })
  })
})

describe('per-site zones and host collisions with other Ingresses', () => {
  const checkHost = async (host: string, site?: string) =>
    (await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host, ...(site ? { site } : {}) } })).json()

  it('a per-site zone is created as asked, and shows its mode', async () => {
    const res = await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'apps.stairfleet.com', ingress: 'per-site' } })
    expect(res.statusCode).toBe(201)
    expect(cluster.created[0].spec).toMatchObject({ domain: 'apps.stairfleet.com', ingress: 'per-site' })
    expect(res.json().ingress).toBe('per-site')
    expect((await app.inject({ method: 'GET', url: '/sites/zones/apps-stairfleet-com' })).json().ingress).toBe('per-site')
  })

  it('check-host refuses a host another Ingress already serves, naming it', async () => {
    cluster.ingresses.push(ing('legacy', 'web', ['beta.dev.stairling.com']))
    const out = await checkHost('beta.dev.stairling.com')
    expect(out.available).toBe(false)
    expect(out.checks).toContainEqual({
      level: 'error', code: 'host_taken',
      message: 'legacy/web serves beta.dev.stairling.com; nothing would be created for this host',
      ingress: { namespace: 'legacy', name: 'web', rule: 'beta.dev.stairling.com', paths: ['/'] },
    })
  })

  it('a foreign wildcard one label above is only shadowed: a warning naming the paths lost; the operator\'s zone wildcard is nothing', async () => {
    expect((await checkHost('new.dev.stairling.com')).checks).toEqual([])
    cluster.ingresses.push(ing('loki', 'loki-alloy', ['*.dev.stairling.com'], {}, ['/collect']))
    const out = await checkHost('new.dev.stairling.com')
    expect(out.available).toBe(true)
    expect(out.checks).toEqual([{
      level: 'warn', code: 'host_shadows_wildcard',
      message: 'loki/loki-alloy serves *.dev.stairling.com; nginx routes new.dev.stairling.com to this Site (paths of that Ingress, e.g. /collect, are not served on this host)',
      ingress: { namespace: 'loki', name: 'loki-alloy', rule: '*.dev.stairling.com', paths: ['/collect'] },
    }])
    // An exact-host Ingress on top of it still blocks.
    cluster.ingresses.push(ing('legacy', 'web', ['new.dev.stairling.com']))
    const both = await checkHost('new.dev.stairling.com')
    expect(both.available).toBe(false)
    expect(both.checks.map((c: { code: string }) => c.code)).toEqual(['host_taken', 'host_shadows_wildcard'])
  })

  it('the Site\'s own Ingress is not a collision for that Site, but is for any other', async () => {
    records = []
    expect((await checkHost('payroll.dev.stairling.com', 'payroll')).available).toBe(true)
    const other = await checkHost('payroll.dev.stairling.com', 'imposter')
    expect(other.checks).toContainEqual(expect.objectContaining({ code: 'host_taken', ingress: expect.objectContaining({ namespace: 'auth', name: 'site-payroll', rule: 'payroll.dev.stairling.com' }) }))
  })

  it('a host outside every zone that another Ingress serves: the suggestion says so', async () => {
    cluster.ingresses.push(ing('shop', 'web', ['shop.apps.stairfleet.com']))
    const out = (await app.inject({ method: 'POST', url: '/sites/zones/suggest', payload: { host: 'shop.apps.stairfleet.com' } })).json()
    expect(out.checks[0]).toMatchObject({ level: 'error', code: 'host_taken', ingress: { namespace: 'shop', name: 'web' } })
  })

  it('a shared domain (hosts with their own Ingress under it) is suggested per-site, with a shadow warning', async () => {
    cluster.zones.clear()
    cluster.ingresses.push(ing('legacy', 'web', ['beta.dev.stairling.com']), ing('grafana', 'grafana', ['grafana.dev.stairling.com']))
    const out = (await app.inject({ method: 'POST', url: '/sites/zones/suggest', payload: { host: 'wiki.dev.stairling.com' } })).json()
    expect(out.ingress).toEqual({
      modes: ['wildcard', 'per-site'],
      suggested: 'per-site',
      shared: [
        { namespace: 'grafana', name: 'grafana', rule: 'grafana.dev.stairling.com' },
        { namespace: 'legacy', name: 'web', rule: 'beta.dev.stairling.com' },
      ],
    })
    expect(out.checks).toContainEqual(expect.objectContaining({ level: 'warn', code: 'wildcard_shadows' }))
    // Creating it as a wildcard anyway is allowed, with the same warning in the answer.
    const res = await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'dev.stairling.com' } })
    expect(res.statusCode).toBe(201)
    expect(res.json().checks).toContainEqual(expect.objectContaining({ code: 'wildcard_shadows' }))
  })

  it('a wildcard zone next to a foreign wildcard for the same domain is refused; per-site is not', async () => {
    cluster.zones.clear()
    cluster.ingresses.push(ing('legacy', 'catch-all', ['*.dev.stairling.com']))
    const sug = (await app.inject({ method: 'POST', url: '/sites/zones/suggest', payload: { host: 'wiki.dev.stairling.com' } })).json()
    expect(sug.ingress.suggested).toBe('per-site')
    expect(sug.checks).toContainEqual(expect.objectContaining({ code: 'wildcard_taken' }))
    const wild = await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'dev.stairling.com' } })
    expect(wild.statusCode).toBe(409)
    expect(wild.json()).toMatchObject({ error: 'wildcard_taken', message: expect.stringContaining('legacy/catch-all') })
    expect((await app.inject({ method: 'POST', url: '/sites/zones', headers: WM, payload: { domain: 'dev.stairling.com', ingress: 'per-site' } })).statusCode).toBe(201)
  })

  it('preview carries host_taken as a blocking check', async () => {
    cluster.ingresses.push(ing('legacy', 'web', ['payroll.dev.stairling.com']))
    const { preview } = await import('../../sites/sites.service.js')
    const gk = await import('../../sites/gatekit.client.js')
    vi.spyOn(gk.gatekit, 'compile').mockResolvedValue([])
    vi.spyOn(gk.gatekit, 'overlap').mockResolvedValue({ overlaps: [] })
    const rbac = await import('../../services/redis-rbac.repository.js')
    vi.spyOn(rbac.redisRbacRepository, 'serviceExists').mockResolvedValue(false)
    vi.spyOn(rbac.redisRbacRepository, 'getGroups').mockResolvedValue({})
    const routeTies = await import('../../policy/route-ties.js')
    vi.spyOn(routeTies, 'loadPublishedRouteRules').mockResolvedValue([] as never)
    const out = await preview(payrollSite())
    expect(out.checks).toContainEqual(expect.objectContaining({ level: 'error', code: 'host_taken', path: 'address.host', ingress: expect.objectContaining({ namespace: 'legacy', name: 'web', rule: 'payroll.dev.stairling.com' }) }))
    expect(out.checks.filter((c: { code: string }) => c.code === 'host_taken')).toHaveLength(1)
  })

  it('503 when the cluster\'s Ingresses cannot be read', async () => {
    cluster.up = false
    expect((await app.inject({ method: 'POST', url: '/sites/check-host', headers: W, payload: { host: 'x.dev.stairling.com' } })).statusCode).toBe(503)
  })
})
