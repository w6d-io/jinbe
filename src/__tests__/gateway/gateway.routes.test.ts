import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// GW-2: /api/admin/gateway. Reads the Gateway CR (or, before one exists, the live Oathkeeper config,
// read-only); writes only the CR spec, with If-Match, `sites:apply` and a recent second factor.

const h = vi.hoisted(() => ({ emit: vi.fn() }))

vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../middleware/require-admin.js', async () => {
  const { enforcing } = await import('../../policy/declared-routes.js')
  return {
    requireSuperAdmin: enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
      if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden' })
    }, 'admin:write'),
    // Same contract as the real guard: `*` or `sites:apply` (super_admin) — keyed on x-test-perm here.
    requireSitesApply: enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
      if (request.headers['x-test-perm'] !== 'sites:apply') return reply.status(403).send({ error: 'Forbidden', message: 'This needs sites:apply.' })
    }, 'sites:apply'),
    requireRecentMfa: async (request: FastifyRequest, reply: FastifyReply) => {
      if (!request.headers['x-test-mfa']) return reply.status(422).send({ error: 'reauth_required' })
    },
  }
})
vi.mock('../../middleware/require-platform-permission.js', async () => {
  const { enforcing } = await import('../../policy/declared-routes.js')
  return {
    requirePlatformPermission: (required: string) => enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
      if (request.headers['x-test-perm'] !== required) return reply.status(403).send({ error: 'Forbidden', message: `This needs ${required}.` })
    }, required),
  }
})

import { gatewayRoutes, setRolloutPolling } from '../../gateway/routes.js'
import { setKubeGateway, PREVIOUS_SPEC_ANNOTATION, type GatewayCr, type GatewaySpec, type KubeGateway } from '../../gateway/kube-gateway.js'
import { GATEWAY_ROUTE_AUDIT } from '../../gateway/audit.js'
import { KubeUnavailable, type SiteCrObject } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import { declaredRoutes, enforcing, guardAll, resetDeclaredRoutes } from '../../policy/declared-routes.js'

const APPLY = { 'x-test-perm': 'sites:apply', 'x-test-mfa': '1' }
const W = { 'x-test-write': '1' }

const spec = (): GatewaySpec => ({
  authenticators: {
    noop: { enabled: true },
    cookie_session: { enabled: true, config: { check_session_url: 'http://kratos/sessions/whoami' } },
    oauth2_introspection: { enabled: true, config: { introspection_url: 'http://hydra/introspect', introspection_request_headers: { Authorization: 'vault:auth/hydra#basic', 'X-Key': 'plain-legacy' } } },
  },
  authorizers: { allow: { enabled: true }, deny: { enabled: true }, remote_json: { enabled: true, config: { remote: 'http://opa/allow', payload: '{}' } } },
  mutators: { noop: { enabled: true }, header: { enabled: true, config: { headers: { 'X-User': '{{ print .Subject }}' } } } },
  errors: { json: { enabled: true }, redirect: { enabled: true, config: { to: 'https://login/' } } },
  errorFallback: ['redirect', 'json'],
})

const site = (name: string, authenticator: string): SiteCrObject => ({
  apiVersion: 'auth.w6d.io/v1alpha1', kind: 'Site',
  metadata: { name, namespace: 'auth', labels: {}, annotations: {} },
  spec: {
    hosts: [`${name}.dev.stairling.com`], upstream: { service: name, namespace: 'apps', port: 80, scheme: 'http', preserveHost: false },
    gates: [{ name: 'main', match: { methods: ['GET'], url: 'x' }, authenticators: [{ handler: authenticator }], authorizer: { handler: 'remote_json' }, mutators: [{ handler: 'header' }] }],
    exposure: { mode: 'zone' }, paused: false,
  },
})

const LIVE_YAML = {
  authenticators: { noop: { enabled: true }, cookie_session: { enabled: true, config: { check_session_url: 'http://kratos/sessions/whoami' } }, oauth2_introspection: { enabled: true, config: { introspection_url: 'http://hydra', pre_authorization: { client_secret: 'clear!' } } } },
  authorizers: { allow: { enabled: true }, deny: { enabled: true }, remote_json: { enabled: true, config: { remote: 'http://opa', payload: '{}' } } },
  mutators: { noop: { enabled: true }, header: { enabled: true, config: { headers: { 'X-User': 'u' } } } },
  errors: { fallback: ['json'], handlers: { json: { enabled: true }, redirect: { enabled: false } } },
}

class FakeKube implements KubeGateway {
  up = true
  cr: GatewayCr | null = null
  live: Record<string, unknown> | null = LIVE_YAML
  sites: SiteCrObject[] = []
  writes: Array<{ cr: GatewayCr; rv: string | null }> = []
  private rv = 10
  private check() { if (!this.up) throw new KubeUnavailable('down') }
  async get() { this.check(); return this.cr ? structuredClone(this.cr) : null }
  async write(cr: GatewayCr, rv: string | null) {
    this.check()
    this.writes.push({ cr: structuredClone(cr), rv })
    this.rv += 1
    const generation = (this.cr?.metadata.generation ?? 0) + 1
    this.cr = { ...structuredClone(cr), metadata: { ...cr.metadata, resourceVersion: String(this.rv), generation }, status: this.cr?.status }
    return structuredClone(this.cr)
  }
  async listSites() { this.check(); return this.sites }
  async liveOathkeeperConfig() { this.check(); return this.live }
}

let kube: FakeKube
let app: FastifyInstance

const managed = (s = spec(), annotations: Record<string, string> = {}): GatewayCr => ({
  apiVersion: 'auth.w6d.io/v1alpha1', kind: 'Gateway',
  metadata: { name: 'gateway', namespace: 'auth', resourceVersion: '7', generation: 3, annotations },
  spec: s,
  status: { observedGeneration: 3, conditions: [{ type: 'Ready', status: 'True' }], rollout: { phase: 'Complete', replicas: 2, updatedReplicas: 2, readyReplicas: 2 } },
})

beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request) => {
    request.userContext = { id: 'sam-id', email: 'sam@x.test', name: 'Sam' }
  })
  await app.register(gatewayRoutes, { prefix: '/gateway' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  process.env.SITES_NAMESPACE = 'auth'
  resetSitesConfig()
  kube = new FakeKube()
  setKubeGateway(kube)
  h.emit.mockReset()
  h.emit.mockResolvedValue(undefined)
  setRolloutPolling(1, 1000)
})

const get = () => app.inject({ method: 'GET', url: '/gateway' })
const put = (body: unknown, headers: Record<string, string> = { ...APPLY, 'if-match': '"rv:7"' }) =>
  app.inject({ method: 'PUT', url: '/gateway', headers, payload: body as Record<string, unknown> })
const byName = (body: { handlers: Array<{ kind: string; name: string }> }, kind: string, name: string) =>
  body.handlers.find((x) => x.kind === kind && x.name === name) as Record<string, unknown>

describe('guards and route table', () => {
  it('publishes: reads admin:read, preview admin:write, put and rollback sites:apply', async () => {
    resetDeclaredRoutes()
    const admin = Fastify()
    await admin.register(async (scope) => {
      guardAll(scope, enforcing(async () => {}, 'admin:read'), () => false)
      await scope.register(gatewayRoutes, { prefix: '/gateway' })
    }, { prefix: '/api/admin' })
    await admin.ready()
    const find = (method: string, path: string) => declaredRoutes().find((r) => r.method === method && r.path === path)?.permission
    expect(find('GET', '/api/admin/gateway')).toBe('admin:read')
    expect(find('GET', '/api/admin/gateway/rollout')).toBe('admin:read')
    expect(find('GET', '/api/admin/gateway/rollout/events')).toBe('admin:read')
    expect(find('POST', '/api/admin/gateway/preview')).toBe('admin:write')
    expect(find('PUT', '/api/admin/gateway')).toBe('sites:apply')
    expect(find('POST', '/api/admin/gateway/rollback')).toBe('sites:apply')
    // AU-2: every mutating route of the module has its audit row.
    const writes = declaredRoutes().filter((r) => r.path.startsWith('/api/admin/gateway') && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(r.method))
    expect(writes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(Object.keys(GATEWAY_ROUTE_AUDIT).sort())
    await admin.close()
  })

  it('a write without sites:apply, or without a recent second factor, is refused and writes nothing', async () => {
    kube.cr = managed()
    expect((await put({ spec: spec() }, { 'x-test-mfa': '1', 'if-match': '"rv:7"' })).statusCode).toBe(403)
    expect((await put({ spec: spec() }, { 'x-test-perm': 'sites:apply', 'if-match': '"rv:7"' })).statusCode).toBe(422)
    expect((await app.inject({ method: 'POST', url: '/gateway/rollback', headers: { 'x-test-perm': 'sites:apply' } })).statusCode).toBe(422)
    expect(kube.writes).toEqual([])
  })

  it('preview needs admin:write', async () => {
    expect((await app.inject({ method: 'POST', url: '/gateway/preview', payload: { spec: spec() } })).statusCode).toBe(403)
  })
})

describe('GET /gateway', () => {
  it('before a Gateway exists: the live Oathkeeper config, managed=false, secrets masked', async () => {
    kube.sites = [site('payroll', 'cookie_session'), site('wiki', 'cookie_session')]
    const res = await get()
    expect(res.statusCode).toBe(200)
    expect(res.headers.etag).toBe('"unmanaged"')
    const body = res.json()
    expect(body).toMatchObject({ managed: false, source: 'oathkeeper-config', errorFallback: ['json'] })
    expect(res.body).not.toContain('clear!')
    const intro = byName(body, 'authenticator', 'oauth2_introspection')
    expect((intro.config as { pre_authorization: { client_secret: string } }).pre_authorization.client_secret).toBe('***')
    const cookie = byName(body, 'authenticator', 'cookie_session')
    expect(cookie.inUse).toEqual(['(platform)', 'payroll', 'wiki'])
    expect(cookie.enabled).toBe(true)
    expect((cookie.fields as unknown[]).length).toBeGreaterThan(5)
    expect(byName(body, 'error', 'redirect').enabled).toBe(false)
    expect(byName(body, 'mutator', 'id_token').locked).toMatch(/Secret/)
    expect(byName(body, 'authenticator', 'jwt')).toMatchObject({ enabled: false, defaults: expect.objectContaining({ jwks_ttl: '30s' }) })
  })

  it('without a ConfigMap either: the env enabled sets', async () => {
    kube.live = null
    const body = (await get()).json()
    expect(body.source).toBe('env')
    expect(byName(body, 'authenticator', 'cookie_session').enabled).toBe(true)
  })

  it('with a Gateway: its spec, rv etag and status', async () => {
    kube.cr = managed()
    const res = await get()
    expect(res.headers.etag).toBe('"rv:7"')
    const body = res.json()
    expect(body).toMatchObject({ managed: true, source: 'gateway-cr', status: { generation: 3, observedGeneration: 3, lastRollout: { phase: 'Complete' } } })
    const headers = (byName(body, 'authenticator', 'oauth2_introspection').config as { introspection_request_headers: Record<string, string> }).introspection_request_headers
    expect(headers).toEqual({ Authorization: 'vault:auth/hydra#basic', 'X-Key': '***' })
  })

  it('503 when the Kubernetes API cannot answer', async () => {
    kube.up = false
    expect((await get()).statusCode).toBe(503)
  })
})

describe('POST /gateway/preview', () => {
  it('returns the verdict and writes nothing', async () => {
    kube.cr = managed()
    kube.sites = [site('payroll', 'oauth2_introspection')]
    const s = spec()
    s.authenticators.oauth2_introspection.enabled = false
    const res = await app.inject({ method: 'POST', url: '/gateway/preview', headers: W, payload: { spec: s } })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ ok: false, managed: true })
    expect(res.json().issues).toContainEqual(expect.objectContaining({ code: 'handler_in_use', handler: 'oauth2_introspection' }))
    expect(kube.writes).toEqual([])
    expect(h.emit).not.toHaveBeenCalled()
  })

  it('400 on a malformed body', async () => {
    const res = await app.inject({ method: 'POST', url: '/gateway/preview', headers: W, payload: { spec: { authenticators: { noop: { on: true } } } } })
    expect(res.statusCode).toBe(400)
  })
})

describe('PUT /gateway', () => {
  it('428 without If-Match, 412 on a stale one', async () => {
    kube.cr = managed()
    expect((await put({ spec: spec() }, APPLY)).statusCode).toBe(428)
    expect((await put({ spec: spec() }, { ...APPLY, 'if-match': '"rv:6"' })).statusCode).toBe(412)
    expect(kube.writes).toEqual([])
  })

  it('422 with the issues, and nothing written, when the proposal is refused', async () => {
    kube.cr = managed()
    const s = spec()
    s.authorizers.remote_json.config = { remote: 'http://opa' }
    const res = await put({ spec: s })
    expect(res.statusCode).toBe(422)
    expect(res.json().issues).toContainEqual(expect.objectContaining({ code: 'field_required', path: 'payload' }))
    expect(kube.writes).toEqual([])
  })

  it('writes the spec at the read resourceVersion, keeps masked secrets, records the previous spec, audits without values', async () => {
    kube.cr = managed()
    const s = spec()
    s.authenticators.oauth2_introspection.config!.introspection_request_headers = { Authorization: 'vault:auth/hydra#basic', 'X-Key': '***' }
    s.authenticators.oauth2_introspection.config!.required_scope = ['read']
    const res = await put({ spec: s, note: 'scope' })
    expect(res.statusCode).toBe(200)
    expect(res.headers.etag).toBe('"rv:11"')
    expect(res.json().changes).toEqual([{ kind: 'authenticator', handler: 'oauth2_introspection', change: 'config', changedKeys: ['required_scope'] }])
    const [w] = kube.writes
    expect(w.rv).toBe('7')
    expect(w.cr.spec.authenticators.oauth2_introspection.config!.introspection_request_headers).toEqual({ Authorization: 'vault:auth/hydra#basic', 'X-Key': 'plain-legacy' })
    expect(JSON.parse(w.cr.metadata.annotations![PREVIOUS_SPEC_ANNOTATION])).toEqual(spec())
    await vi.waitFor(() => expect(h.emit).toHaveBeenCalledTimes(1))
    const ev = h.emit.mock.calls[0][0]
    expect(ev).toMatchObject({ v1Event: 'gateway.changed', targetType: 'gateway', actor: { email: 'sam@x.test' } })
    expect(JSON.stringify(ev)).not.toContain('plain-legacy')
    expect(JSON.stringify(ev)).not.toContain('vault:')
  })

  it('refuses a clear secret', async () => {
    kube.cr = managed()
    const s = spec()
    s.authenticators.oauth2_introspection.config!.introspection_request_headers = { Authorization: 'Basic abc' }
    const res = await put({ spec: s })
    expect(res.statusCode).toBe(422)
    expect(res.json().issues[0]).toMatchObject({ code: 'secret_not_a_vault_ref', path: 'introspection_request_headers.Authorization' })
  })

  it('adopts the live config: creates the CR (If-Match "unmanaged"), with no previous spec', async () => {
    const s = spec()
    s.authenticators.oauth2_introspection.config!.introspection_request_headers = { Authorization: 'vault:auth/hydra#basic' }
    const res = await put({ spec: s }, { ...APPLY, 'if-match': '"unmanaged"' })
    expect(res.statusCode).toBe(200)
    expect(kube.writes[0].rv).toBeNull()
    expect(kube.writes[0].cr.metadata.annotations?.[PREVIOUS_SPEC_ANNOTATION]).toBeUndefined()
    expect(kube.writes[0].cr).toMatchObject({ kind: 'Gateway', metadata: { name: 'gateway', namespace: 'auth' } })
  })

  it('adopting refuses to copy a clear live secret into the CR', async () => {
    const s = spec()
    s.authenticators.oauth2_introspection.config = { introspection_url: 'http://hydra', pre_authorization: { client_secret: '***' } }
    const res = await put({ spec: s }, { ...APPLY, 'if-match': '"unmanaged"' })
    expect(res.statusCode).toBe(422)
    expect(kube.writes).toEqual([])
  })
})

describe('rollback', () => {
  const rollback = () => app.inject({ method: 'POST', url: '/gateway/rollback', headers: APPLY, payload: {} })

  it('404 before a Gateway exists, 409 without a previous spec', async () => {
    expect((await rollback()).statusCode).toBe(404)
    kube.cr = managed()
    expect((await rollback()).statusCode).toBe(409)
  })

  it('writes the previous spec back and records the current one as previous', async () => {
    const before = spec()
    before.authenticators.oauth2_introspection.config!.required_scope = ['old']
    kube.cr = managed(spec(), { [PREVIOUS_SPEC_ANNOTATION]: JSON.stringify(before) })
    const res = await rollback()
    expect(res.statusCode).toBe(200)
    expect(kube.writes[0].cr.spec).toEqual(before)
    expect(JSON.parse(kube.writes[0].cr.metadata.annotations![PREVIOUS_SPEC_ANNOTATION])).toEqual(spec())
    await vi.waitFor(() => expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ v1Event: 'gateway.rolled_back' })))
  })

  it('refuses a rollback that would disable a handler a site now uses', async () => {
    const before = spec()
    before.authenticators.oauth2_introspection.enabled = false
    kube.cr = managed(spec(), { [PREVIOUS_SPEC_ANNOTATION]: JSON.stringify(before) })
    kube.sites = [site('api', 'oauth2_introspection')]
    const res = await rollback()
    expect(res.statusCode).toBe(422)
    expect(res.json().issues).toContainEqual(expect.objectContaining({ code: 'handler_in_use' }))
    expect(kube.writes).toEqual([])
  })
})

describe('rollout', () => {
  it('reports the status and whether the rollout settled', async () => {
    kube.cr = managed()
    kube.cr.metadata.generation = 4
    kube.cr.status!.rollout = { phase: 'Progressing', replicas: 2, updatedReplicas: 1 }
    const body = (await app.inject({ method: 'GET', url: '/gateway/rollout' })).json()
    expect(body).toMatchObject({ managed: true, settled: false, generation: 4, observedGeneration: 3, rollout: { phase: 'Progressing' } })
  })

  it('streams status changes as SSE until settled', async () => {
    kube.cr = managed()
    kube.cr.metadata.generation = 4
    kube.cr.status!.rollout = { phase: 'Progressing', replicas: 2, updatedReplicas: 1 }
    let calls = 0
    const orig = kube.get.bind(kube)
    kube.get = async () => {
      calls += 1
      if (calls === 3) kube.cr!.status = { observedGeneration: 4, rollout: { phase: 'Complete', replicas: 2, updatedReplicas: 2, readyReplicas: 2 } }
      return orig()
    }
    const res = await app.inject({ method: 'GET', url: '/gateway/rollout/events' })
    expect(res.headers['content-type']).toBe('text/event-stream')
    const events = res.body.split('\n\n').filter((e) => e.startsWith('event: rollout'))
    expect(events).toHaveLength(2)
    expect(events[1]).toContain('"settled":true')
    expect(res.body).toContain(': keep-alive')
  })
})
