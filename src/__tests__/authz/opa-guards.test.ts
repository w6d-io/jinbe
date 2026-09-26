import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// AZ-1: every app-layer guard asks OPA — the engine the gateway decides with — over HTTP, with its
// bearer token. OPA is mocked at the HTTP boundary only: what jinbe sends is asserted, and what OPA
// answers is obeyed. The ConfigMap model is never read.

const s = vi.hoisted(() => ({
  opaDown: false,
  calls: [] as Array<{ rule: string; auth: string | null; input: Record<string, unknown> }>,
  configMapReads: 0,
}))

vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  const over: Record<string, unknown> = { OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret', DEV_BYPASS_AUTH: false }
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in over ? over[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../config/index.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/index.js')>()
  const over: Record<string, unknown> = { OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret', DEV_BYPASS_AUTH: false }
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in over ? over[k as string] : t[k as keyof typeof t]) }) }
})
// The old model reader, if anything still reached it: in-cluster namespace + a ConfigMap list.
vi.mock('node:fs/promises', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs/promises')>()
  return {
    ...real,
    readFile: vi.fn(async (p: string, ...rest: unknown[]) =>
      String(p).includes('serviceaccount/namespace') ? 'jinbe' : (real.readFile as (...a: unknown[]) => unknown)(p, ...rest)),
  }
})
vi.mock('@kubernetes/client-node', async (importOriginal) => {
  const real = await importOriginal<typeof import('@kubernetes/client-node')>()
  class KubeConfig {
    loadFromCluster() {}
    loadFromDefault() {}
    makeApiClient() {
      return {
        listNamespacedConfigMap: vi.fn(async () => {
          s.configMapReads++
          return { items: [{ metadata: { name: 'model' }, data: { 'groups.json': '{"everyone":{"*":["root"]}}', 'roles.json': '{"root":["*","admin:read","admin:write","sites:apply"]}' } }] }
        }),
      }
    }
  }
  return { ...real, KubeConfig }
})
vi.mock('../../services/organisation-store.js', () => ({
  groupsForSubjects: vi.fn(async (ids: string[]) => new Map(ids.map((id) => [id, ['everyone']]))),
  organisationsForSubject: vi.fn(async () => ['acme', 'globex']),
  membersOf: vi.fn(async () => []),
  organisationStoreConfigured: () => false,
}))
vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { getOrgAdmins: vi.fn(async () => ['acme-admin@example.com', 'super@example.com']) },
}))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => 'id') } }))

// ── the world OPA holds (Redis → OPAL), as the stand-in answers it ──
const JINBE: Record<string, string[]> = {
  super: ['*'],
  admin: ['admin:read', 'admin:write'],
  support: ['sessions:read', 'sessions:revoke', 'users:read', 'users:recovery', 'users:send_login_link', 'users:update', 'users:update_email'],
  'acme-admin': [],
  nobody: [],
}
const MANAGEABLE: Record<string, string[]> = { 'acme-admin': ['acme'], super: [] }
const MEMBER: Record<string, string[]> = { 'acme-admin': ['acme'], super: [] }
const who = (email: unknown) => String(email).split('@')[0]

function answer(rule: string, input: Record<string, unknown>): unknown {
  switch (rule) {
    case 'rbac/user_info':
      return { email: input.email, app: input.app, groups: [], roles: [], permissions: JINBE[who(input.email)] ?? [] }
    case 'rbac/super_admin':
      return who(input.email) === 'super'
    case 'rbac/delegation/manageable_orgs':
      return MANAGEABLE[who((input.actor as { email: string }).email)] ?? []
    case 'rbac/caller_organizations':
      return MEMBER[who(input.email)] ?? []
    case 'rbac/decision': {
      // The org layer: super_admin, or the roster admin of the org named in the path.
      const u = who(input.email)
      const org = String(input.object).split('/')[3]
      const allow = u === 'super' || (MANAGEABLE[u] ?? []).includes(org)
      return { allow, groups: [], organizations: MEMBER[u] ?? [], reason: allow ? 'ok' : 'forbidden' }
    }
  }
  return undefined
}

import { requireAdmin, requireSuperAdmin, requireSitesApply } from '../../middleware/require-admin.js'
import { requirePlatformPermission } from '../../middleware/require-platform-permission.js'
import { requirePermission } from '../../middleware/require-permission.js'
import { requireServiceAdmin } from '../../middleware/require-service-admin.js'
import { requireManageableOrg } from '../../middleware/require-manageable-org.js'
import { requireOrgAdmin, requireOrgPermission } from '../../middleware/require-org-permission.js'
import { clearAuthzCache } from '../../authz/opa.js'

let app: FastifyInstance
beforeAll(async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string | URL, init?: RequestInit) => {
    const u = String(url)
    const rule = u.replace('http://opal-client:8181/v1/data/', '')
    const body = JSON.parse(String(init?.body ?? '{}')) as { input: Record<string, unknown> }
    s.calls.push({ rule, auth: new Headers(init?.headers).get('authorization'), input: body.input })
    if (s.opaDown) throw new TypeError('fetch failed')
    return Response.json({ result: answer(rule, body.input) })
  }))

  app = Fastify()
  app.addHook('onRequest', async (request) => {
    const u = request.headers['x-test-user'] as string | undefined
    if (u) request.userContext = { id: `id-${u}`, email: `${u}@example.com`, name: u, aal: 'aal2', authVia: 'session' } as never
  })
  const ok = async (request: { rbacInfo?: unknown }) => ({ ok: true, rbacInfo: request.rbacInfo ?? null })
  await app.register(async (api) => {
    api.get('/t/admin', { preHandler: requireAdmin }, ok)
    api.post('/t/super', { preHandler: requireSuperAdmin }, ok)
    api.post('/t/sites', { preHandler: requireSitesApply }, ok)
    api.get('/t/platform', { preHandler: requirePlatformPermission('admin.organisation:read') }, ok)
    api.get('/t/users', { preHandler: requirePermission('users:read') }, ok)
    api.put('/t/groups', { preHandler: requirePermission('users:assign_group') }, ok)
    await api.register(async (org) => {
      org.get('/users', { preHandler: [requireServiceAdmin('organizationId', { orgAdmin: true }), requireManageableOrg()] }, ok)
      org.get('/grants', { preHandler: requireOrgAdmin('organizationId') }, ok)
      org.get('/api-keys', { preHandler: requireOrgPermission('org:manage_api_keys') }, ok)
    }, { prefix: '/organizations/:organizationId' })
  }, { prefix: '/api' })
  await app.ready()
})
afterAll(async () => {
  await app.close()
  vi.unstubAllGlobals()
})
beforeEach(() => {
  s.opaDown = false
  s.calls.length = 0
  s.configMapReads = 0
  clearAuthzCache()
})

const call = (method: 'GET' | 'POST' | 'PUT', url: string, user: string) =>
  app.inject({ method, url, headers: { 'x-test-user': user } })

const GUARDED: Array<['GET' | 'POST' | 'PUT', string]> = [
  ['GET', '/api/t/admin'],
  ['POST', '/api/t/super'],
  ['POST', '/api/t/sites'],
  ['GET', '/api/t/platform'],
  ['GET', '/api/t/users'],
  ['PUT', '/api/t/groups'],
  ['GET', '/api/organizations/acme/users'],
  ['GET', '/api/organizations/acme/grants'],
  ['GET', '/api/organizations/acme/api-keys'],
]

describe('AZ-1 — app-layer guards decide on OPA only', () => {
  it('each platform guard asks rbac/user_info for jinbe, with the bearer token', async () => {
    for (const [method, url] of GUARDED.slice(0, 6)) {
      clearAuthzCache()
      s.calls.length = 0
      await call(method, url, 'admin')
      expect(s.calls, url).toEqual([
        { rule: 'rbac/user_info', auth: 'Bearer opa-secret', input: { email: 'admin@example.com', app: 'jinbe' } },
      ])
    }
  })

  it('the org member-management guard asks rbac/decision for the request itself', async () => {
    await call('GET', '/api/organizations/acme/users?limit=5', 'acme-admin')
    expect(s.calls.find((c) => c.rule === 'rbac/decision')?.input).toEqual({
      email: 'acme-admin@example.com',
      object: '/api/organizations/acme/users',
      action: 'GET',
      app: 'jinbe',
      aal: 'aal2',
      client: false,
    })
  })

  it('the org-admin guard asks super_admin and manageable_orgs', async () => {
    await call('GET', '/api/organizations/acme/grants', 'acme-admin')
    expect(s.calls.map((c) => [c.rule, c.input])).toEqual([
      ['rbac/super_admin', { email: 'acme-admin@example.com', app: 'jinbe' }],
      ['rbac/delegation/manageable_orgs', { actor: { email: 'acme-admin@example.com' } }],
    ])
  })

  it('never reads the ConfigMap model', async () => {
    for (const [method, url] of GUARDED) for (const u of ['super', 'admin', 'support', 'acme-admin', 'nobody']) await call(method, url, u)
    expect(s.configMapReads).toBe(0)
  })

  it('OPA down → 503 on every guarded route, never 403 and never an allow', async () => {
    s.opaDown = true
    for (const [method, url] of GUARDED) {
      const res = await call(method, url, 'super')
      expect(res.statusCode, `${method} ${url}`).toBe(503)
    }
  })

  it('super_admin (`*`) passes every guard', async () => {
    for (const [method, url] of GUARDED) {
      const res = await call(method, url, 'super')
      expect(res.statusCode, `${method} ${url}`).toBe(200)
    }
  })

  it('org admin of Acme manages Acme members and is refused Globex — OPA decides', async () => {
    expect((await call('GET', '/api/organizations/acme/users', 'acme-admin')).statusCode).toBe(200)
    expect((await call('GET', '/api/organizations/globex/users', 'acme-admin')).statusCode).toBe(403)
    expect((await call('GET', '/api/organizations/acme/grants', 'acme-admin')).statusCode).toBe(200)
    expect((await call('GET', '/api/organizations/globex/grants', 'acme-admin')).statusCode).toBe(403)
    expect((await call('GET', '/api/organizations/acme/api-keys', 'acme-admin')).statusCode).toBe(200)
    expect((await call('GET', '/api/organizations/globex/api-keys', 'acme-admin')).statusCode).toBe(403)
    // Holding nothing on the platform: the admin surfaces stay shut.
    expect((await call('GET', '/api/t/admin', 'acme-admin')).statusCode).toBe(403)
  })

  it('support (Redis-seeded role) passes user routes and is refused admin, group and site writes', async () => {
    expect((await call('GET', '/api/t/users', 'support')).statusCode).toBe(200)
    expect((await call('GET', '/api/t/admin', 'support')).statusCode).toBe(403)
    expect((await call('POST', '/api/t/super', 'support')).statusCode).toBe(403)
    expect((await call('PUT', '/api/t/groups', 'support')).statusCode).toBe(403)
    expect((await call('POST', '/api/t/sites', 'support')).statusCode).toBe(403)
    expect((await call('GET', '/api/organizations/acme/users', 'support')).statusCode).toBe(403)
  })

  it('an administrator holding admin:read/admin:write passes the admin guards but not sites:apply', async () => {
    expect((await call('GET', '/api/t/admin', 'admin')).statusCode).toBe(200)
    expect((await call('POST', '/api/t/super', 'admin')).statusCode).toBe(200)
    expect((await call('GET', '/api/t/platform', 'admin')).statusCode).toBe(200)
    expect((await call('POST', '/api/t/sites', 'admin')).statusCode).toBe(403)
  })

  it('answers are cached (≤5 s): a burst asks OPA once', async () => {
    for (let i = 0; i < 5; i++) await call('GET', '/api/t/admin', 'admin')
    expect(s.calls.filter((c) => c.rule === 'rbac/user_info')).toHaveLength(1)
  })
})
