import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { installRouteAccess } from '../../policy/route-access.js'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// Mandatory 2FA for privileged groups: the setting (rbac:config second_factor_groups → OPAL
// data.second_factor), login-ui's status endpoint (/api/public/second-factor), and the server-side
// hook that honours the policy's `needs_2fa` for jinbe's own routes.

const h = vi.hoisted(() => ({
  opa: vi.fn(),
  session: vi.fn(),
  methods: vi.fn(),
  config: {} as Record<string, string>,
  // The default switch follows the roles: ops can write and super_admins holds '*' (on); readers and
  // staff-viewers only read, and staff-auditors is off by the owner's decision (off).
  groups: {
    super_admins: { global: ['super_admin'] },
    ops: { jinbe: ['operator'] },
    readers: { jinbe: ['viewer'] },
    'staff-viewers': { global: ['viewer'] },
    'staff-auditors': { global: ['auditor'] },
    users: {},
  } as Record<string, unknown>,
  roles: {
    global: { super_admin: ['*'], viewer: ['sites:read', 'access:check'], auditor: ['audit:read', 'audit:export'] },
    jinbe: { operator: ['sites:read', 'sites:apply'], viewer: ['sites:read'] },
  } as Record<string, Record<string, string[]>>,
  schedule: vi.fn(),
  emit: vi.fn(async () => 'id'),
}))

vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  const over: Record<string, unknown> = { OPAL_CLIENT_TOKEN: 'opal-tok' }
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in over ? over[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../services/opa-client.js', async (orig) => {
  const real = await orig<typeof import('../../services/opa-client.js')>()
  return { ...real, queryOpa: h.opa }
})
vi.mock('../../services/kratos-session.service.js', async (orig) => {
  const real = await orig<typeof import('../../services/kratos-session.service.js')>()
  return { ...real, kratosSessionService: { validateSession: h.session } }
})
vi.mock('../../services/kratos.service.js', async (orig) => {
  const real = await orig<typeof import('../../services/kratos.service.js')>()
  return { ...real, kratosService: { mfaMethodsOf: h.methods } }
})
vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getConfig: vi.fn(async () => ({ ...h.config })),
    setConfig: vi.fn(async (k: string, v: string) => { h.config[k] = v }),
    getGroups: vi.fn(async () => h.groups),
    getRoles: vi.fn(async (scope: string) => h.roles[scope] ?? null),
    getServices: vi.fn(async () => []),
  },
}))
vi.mock('../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => unknown) => fn() }))
vi.mock('../../services/opal-publisher.js', () => ({ opalPublisher: { schedule: h.schedule } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../middleware/require-permission.js', async () => (await import('../helpers/permission-stand-ins.js')).permissionStandIn({ readHeader: 'x-test-admin' }))
vi.mock('../../middleware/require-admin.js', async () => (await import('../helpers/permission-stand-ins.js')).adminStandIn())

import { clearAuthzCache } from '../../authz/opa.js'
import { KratosService } from '../../services/kratos.service.js'
import { buildOpalDatasourceEntries } from '../../services/opal-datasource.js'
import { rbacOpalRoutes } from '../../routes/rbac-opal.routes.js'
import { requireSecondFactor } from '../../second-factor/gate.js'
import { secondFactorPublicRoutes, secondFactorRbacRoutes, secondFactorSettingsRoutes } from '../../second-factor/routes.js'
import { defaultRequired, migrateSecondFactorFlags, parseFlags, parseGroups, resetSecondFactorSettingsCache } from '../../second-factor/settings.js'
import { declaredRoute } from '../../policy/declared-routes.js'
import { CATALOG } from '../../policy/catalog.js'
import { ROLES, STAFF_ROLES } from '../../policy/roles.js'
import { resetSecondFactorStatusCache } from '../../second-factor/status.js'

const OPAL = { authorization: 'Bearer opal-tok' }
const COOKIE = 'ory_kratos_session=abc; other=x'
const sessionOf = (email: string, aal: string) => ({
  session: { identityId: `id-${email}`, email, aal, sessionId: 's', secondFactorAt: null },
})

/** OPA stand-in: second_factor_required for root@, decision needs_2fa for root@ below aal2 on /api/admin/*. */
function opaWorld(rule: string, input: Record<string, unknown>) {
  if (rule === 'rbac/second_factor_required') return input.email === 'root@x.io'
  if (rule === 'rbac/user_info') return { groups: input.email === 'root@x.io' ? ['ops', 'super_admins'] : [], roles: [], permissions: [] }
  if (rule === 'rbac/decision') {
    const admin = String(input.object).startsWith('/api/admin/')
    if (!admin) return { allow: false, reason: 'not_found' }
    if (input.email === 'root@x.io' && input.aal !== 'aal2') return { allow: false, reason: 'needs_2fa' }
    if (input.email === 'nobody@x.io') return { allow: false, reason: 'forbidden' }
    return { allow: true, reason: 'ok' }
  }
  return undefined
}

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  // Stand-in for extractIdentity: the test says who the caller is and how they were proven.
  app.addHook('onRequest', async (request) => {
    const email = request.headers['x-email'] as string | undefined
    if (email) {
      request.userContext = {
        email, id: `id-${email}`, name: email,
        aal: request.headers['x-aal'] as string | undefined,
        authVia: (request.headers['x-via'] as 'session' | 'bearer' | undefined) ?? 'session',
      }
    }
  })
  app.addHook('onRequest', requireSecondFactor)
  await app.register(async (api) => {
    await api.register(secondFactorSettingsRoutes, { prefix: '/admin/settings' })
    await api.register(secondFactorPublicRoutes, { prefix: '/public/second-factor' })
    await api.register(rbacOpalRoutes, { prefix: '/admin/rbac' })
    await api.register(secondFactorRbacRoutes, { prefix: '/admin/rbac' })
    api.get('/admin/users', { config: { access: 'authenticated' } }, async () => ({ ok: true }))
    api.get('/whoami', { config: { access: 'public' } }, async () => ({ ok: true }))
  }, { prefix: '/api' })
  await app.ready()
})
afterAll(async () => { await app.close() })

beforeEach(() => {
  for (const k of Object.keys(h.config)) delete h.config[k]
  h.opa.mockImplementation(async (rule: string, input: Record<string, unknown>) => opaWorld(rule, input))
  h.session.mockResolvedValue({ session: null })
  h.methods.mockResolvedValue([])
  h.schedule.mockClear()
  h.emit.mockClear()
  clearAuthzCache()
  resetSecondFactorSettingsCache()
  resetSecondFactorStatusCache()
})

describe('the per-group "Members must use 2FA" switch (one flag: sign-in at aal2 and enrolment before joining)', () => {
  const opal = async () => (await app.inject({ method: 'GET', url: '/api/admin/rbac/opal/second_factor', headers: OPAL })).json()
  const flagsStored = () => JSON.parse(h.config.second_factor_group_flags ?? '{}')
  const WRITE = { 'x-test-write': '1', 'x-test-mfa': '1', 'x-email': 'a@x.io', 'x-aal': 'aal2' }

  it('defaults: on for a group that can write or holds *, off for read-only groups, staff-viewers and staff-auditors', async () => {
    expect(await opal()).toEqual({ groups: ['ops', 'super_admins'] })
    expect(defaultRequired('staff-auditors', { global: ['auditor'] }, { global: h.roles.global })).toBe(false)
    expect(defaultRequired('other-auditors', { global: ['auditor'] }, { global: h.roles.global })).toBe(true) // audit:export writes
    expect(defaultRequired('users', {}, {})).toBe(false)
  })

  it('a stored value overrides the default either way', async () => {
    h.config.second_factor_group_flags = JSON.stringify({ super_admins: false, readers: true })
    expect(await opal()).toEqual({ groups: ['ops', 'readers'] })
  })

  it('the legacy list counts as explicit ON for the groups it named, hyphens included', async () => {
    h.config.second_factor_groups = JSON.stringify(['staff-viewers'])
    expect(await opal()).toEqual({ groups: ['ops', 'staff-viewers', 'super_admins'] })
    expect(parseGroups('["staff-ops","admins","staff-ops"]')).toEqual(['admins', 'staff-ops'])
    expect(parseGroups('["Bad Name"]')).toBeNull()
    expect(parseFlags('{"staff-ops":true,"Bad Name":true,"x":"yes"}')).toEqual({ 'staff-ops': true })
  })

  it('the boot migration pins every unset group to its default and keeps stored values; a second run writes nothing', async () => {
    h.config.second_factor_group_flags = JSON.stringify({ ops: false })
    const { pinned } = await migrateSecondFactorFlags({ info: () => {} })
    expect(pinned.sort()).toEqual(['readers', 'staff-auditors', 'staff-viewers', 'super_admins', 'users'])
    expect(flagsStored()).toEqual({ ops: false, readers: false, 'staff-auditors': false, 'staff-viewers': false, super_admins: true, users: false })
    expect(h.schedule).toHaveBeenCalledWith('second_factor')
    h.schedule.mockClear()
    expect((await migrateSecondFactorFlags({ info: () => {} })).pinned).toEqual([])
    expect(h.schedule).not.toHaveBeenCalled()
  })

  it('the OPAL data source answers 503 when the store cannot be read, so OPA keeps what it holds', async () => {
    const { redisRbacRepository } = await import('../../services/redis-rbac.repository.js')
    vi.mocked(redisRbacRepository.getConfig).mockRejectedValueOnce(new Error('down'))
    const res = await app.inject({ method: 'GET', url: '/api/admin/rbac/opal/second_factor', headers: OPAL })
    expect(res.statusCode).toBe(503)
  })

  it('is part of the OPAL manifest at /second_factor', async () => {
    const entries = await buildOpalDatasourceEntries()
    expect(entries.find((e) => e.dst_path === '/second_factor')?.url).toMatch(/\/api\/admin\/rbac\/opal\/second_factor$/)
  })

  it('the settings screen reads the groups switched on, with the default-on groups beside them', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/admin/settings/second-factor', headers: { 'x-test-admin': '1', 'x-email': 'a@x.io', 'x-aal': 'aal2' } })
    expect(res.statusCode, res.body).toBe(200)
    expect(res.json()).toEqual({ groups: ['ops', 'super_admins'], defaultGroups: ['ops', 'super_admins'] })
  })

  it('PUT one group: stored, published to OPA, audited, and read back as group_setting', async () => {
    const res = await app.inject({ method: 'PUT', url: '/api/admin/rbac/groups/staff-viewers/second-factor', headers: WRITE, payload: { required: true } })
    expect(res.statusCode, res.body).toBe(200)
    expect(res.json()).toEqual({ name: 'staff-viewers', secondFactor: { required: true, source: 'group_setting', enrolBeforeJoining: true, defaultRequired: false } })
    expect(flagsStored()).toEqual({ 'staff-viewers': true })
    expect(h.schedule).toHaveBeenCalledWith('second_factor')
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({
      target: 'second-factor-groups',
      details: { group: 'staff-viewers', before: { required: false, explicit: false }, after: { required: true } },
    }))
    expect(await opal()).toEqual({ groups: ['ops', 'staff-viewers', 'super_admins'] })
  })

  it('PUT one group: groups.mfa:write (super admin alone) and a recent second factor; unknown group 404', async () => {
    const noPerm = await app.inject({ method: 'PUT', url: '/api/admin/rbac/groups/ops/second-factor', headers: { 'x-email': 'a@x.io', 'x-aal': 'aal2', 'x-test-mfa': '1' }, payload: { required: false } })
    expect(noPerm.statusCode).toBe(403)
    const stale = await app.inject({ method: 'PUT', url: '/api/admin/rbac/groups/ops/second-factor', headers: { 'x-test-write': '1', 'x-email': 'a@x.io', 'x-aal': 'aal2' }, payload: { required: false } })
    expect(stale.statusCode).toBe(422)
    const ghost = await app.inject({ method: 'PUT', url: '/api/admin/rbac/groups/ghosts/second-factor', headers: WRITE, payload: { required: true } })
    expect(ghost.statusCode).toBe(404)
    expect(h.config.second_factor_group_flags).toBeUndefined()
    expect(declaredRoute('PUT', '/api/admin/rbac/groups/:name/second-factor')).toMatchObject({ permission: 'groups.mfa:write', stepUp: true })
    expect(CATALOG['groups.mfa:write']).toMatchObject({ stepUp: true, delegable: 'never' })
    expect(STAFF_ROLES.filter((r) => (ROLES[r].permissions as readonly string[]).includes('groups.mfa:write'))).toEqual(['super_admin'])
  })

  it('PUT the list: listed groups on, every other group off; stored as switches and audited', async () => {
    const res = await app.inject({ method: 'PUT', url: '/api/admin/settings/second-factor', headers: WRITE, payload: { groups: ['readers', 'super_admins', 'readers'] } })
    expect(res.statusCode, res.body).toBe(200)
    expect(res.json().groups).toEqual(['readers', 'super_admins'])
    expect(flagsStored()).toEqual({ ops: false, readers: true, 'staff-auditors': false, 'staff-viewers': false, super_admins: true, users: false })
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ target: 'second-factor-groups', details: { before: ['ops', 'super_admins'], after: ['readers', 'super_admins'] } }))
  })

  it('refuses unknown or malformed group names, and changes nothing', async () => {
    const unknown = await app.inject({ method: 'PUT', url: '/api/admin/settings/second-factor', headers: WRITE, payload: { groups: ['ghosts'] } })
    expect(unknown.statusCode).toBe(400)
    expect(unknown.json().error).toBe('unknown_group')
    const bad = await app.inject({ method: 'PUT', url: '/api/admin/settings/second-factor', headers: WRITE, payload: { groups: ['Ops Team'] } })
    expect(bad.json().error).toBe('invalid_group')
    expect(h.config.second_factor_group_flags).toBeUndefined()
    expect(h.schedule).not.toHaveBeenCalled()
  })

  it('writing needs a recent second factor, not only super_admin', async () => {
    const res = await app.inject({ method: 'PUT', url: '/api/admin/settings/second-factor', headers: { 'x-test-write': '1', 'x-email': 'a@x.io', 'x-aal': 'aal2' }, payload: { groups: [] } })
    expect(res.statusCode).toBe(422)
    expect(h.config.second_factor_group_flags).toBeUndefined()
  })
})

describe('GET /api/public/second-factor (login-ui, own session only)', () => {
  const get = (cookie?: string) => app.inject({ method: 'GET', url: '/api/public/second-factor', headers: cookie ? { cookie } : {} })

  it('401 without a Kratos session cookie, and only session cookies are forwarded', async () => {
    expect((await get()).statusCode).toBe(401)
    expect((await get(COOKIE)).statusCode).toBe(401)
    expect(h.session).toHaveBeenCalledWith('ory_kratos_session=abc')
  })

  it('super admin without a factor: required, none enrolled', async () => {
    h.session.mockResolvedValue(sessionOf('root@x.io', 'aal1'))
    const res = await get(COOKIE)
    expect(res.statusCode).toBe(200)
    expect(res.headers['cache-control']).toBe('private, no-store')
    expect(res.json()).toEqual({ secondFactorRequired: true, hasSecondFactor: false, methods: [], aal: 'aal1' })
    expect(h.opa).toHaveBeenCalledWith('rbac/second_factor_required', { email: 'root@x.io' })
  })

  it('super admin with TOTP at aal1: required, enrolled (login-ui steps up)', async () => {
    h.session.mockResolvedValue(sessionOf('root@x.io', 'aal1'))
    h.methods.mockResolvedValue(['totp'])
    expect((await get(COOKIE)).json()).toEqual({ secondFactorRequired: true, hasSecondFactor: true, methods: ['totp'], aal: 'aal1' })
  })

  it('a normal user is not required', async () => {
    h.session.mockResolvedValue(sessionOf('nina@x.io', 'aal1'))
    expect((await get(COOKIE)).json().secondFactorRequired).toBe(false)
  })

  it('503 policy_unavailable when OPA cannot answer (or predates the rule) — login-ui then does not block', async () => {
    h.session.mockResolvedValue(sessionOf('root@x.io', 'aal1'))
    h.opa.mockResolvedValue(undefined)
    const res = await get(COOKIE)
    expect(res.statusCode).toBe(503)
    expect(res.json().error).toBe('policy_unavailable')
  })

  it('503 identity_unavailable when Kratos cannot list the factors', async () => {
    h.session.mockResolvedValue(sessionOf('root@x.io', 'aal1'))
    h.methods.mockRejectedValue(new Error('kratos down'))
    expect((await get(COOKIE)).json().error).toBe('identity_unavailable')
  })

  it('"required, none enrolled" is never cached: enrolling shows at once', async () => {
    h.session.mockResolvedValue(sessionOf('root@x.io', 'aal1'))
    expect((await get(COOKIE)).json().hasSecondFactor).toBe(false)
    h.methods.mockResolvedValue(['totp'])
    expect((await get(COOKIE)).json().hasSecondFactor).toBe(true)
  })

  it('other answers are cached briefly per identity + level', async () => {
    h.session.mockResolvedValue(sessionOf('nina@x.io', 'aal1'))
    await get(COOKIE)
    await get(COOKIE)
    expect(h.methods).toHaveBeenCalledTimes(1)
    h.session.mockResolvedValue(sessionOf('nina@x.io', 'aal2'))
    await get(COOKIE)
    expect(h.methods).toHaveBeenCalledTimes(2)
  })
})

describe('server-side enforcement (onRequest hook: the policy\'s second_factor_required, then needs_2fa)', () => {
  const call = (headers: Record<string, string>, url = '/api/admin/users') => app.inject({ method: 'GET', url, headers })

  it('super admin session at aal1 → 422 second_factor_required, handler never runs', async () => {
    const res = await call({ 'x-email': 'root@x.io', 'x-aal': 'aal1' })
    expect(res.statusCode).toBe(422)
    expect(res.json()).toMatchObject({ error: 'second_factor_required', stepUp: { requiredAal: 'aal2' } })
    expect(h.opa).toHaveBeenCalledWith('rbac/second_factor_required', { email: 'root@x.io' })
  })

  it('the refusal names the rule and the groups that require it (their switches: ops and super_admins)', async () => {
    const res = await call({ 'x-email': 'root@x.io', 'x-aal': 'aal1' })
    expect(res.json()).toMatchObject({ secondFactor: { rule: 'group_sign_in', requiredAal: 'aal2', requiredBecause: ['ops', 'super_admins'] } })
    expect(res.json().message).toContain('ops, super_admins')
  })

  it('super admin at aal2 passes', async () => {
    expect((await call({ 'x-email': 'root@x.io', 'x-aal': 'aal2' })).statusCode).toBe(200)
  })

  it('a session without a known level is judged as aal1', async () => {
    expect((await call({ 'x-email': 'root@x.io' })).statusCode).toBe(422)
  })

  it('a normal user at aal1 passes', async () => {
    expect((await call({ 'x-email': 'nina@x.io', 'x-aal': 'aal1' })).statusCode).toBe(200)
  })

  it('a route jinbe\'s route_map does not describe is still gated (sandbox: GET /api/admin/sites at aal1 was 200)', async () => {
    h.opa.mockImplementation(async (rule: string, input: Record<string, unknown>) =>
      rule === 'rbac/decision' ? { allow: false, reason: 'not_found' } : opaWorld(rule, input))
    const res = await call({ 'x-email': 'root@x.io', 'x-aal': 'aal1' }, '/api/admin/users')
    expect(res.statusCode).toBe(422)
    expect(h.opa).toHaveBeenCalledWith('rbac/second_factor_required', { email: 'root@x.io' })
  })

  it('jinbe\'s own per-site 2FA (the gateway\'s needs_2fa) still applies to someone the group rule does not name', async () => {
    h.opa.mockImplementation(async (rule: string, input: Record<string, unknown>) =>
      rule === 'rbac/decision' && input.email === 'nina@x.io' ? { allow: false, reason: 'needs_2fa' } : opaWorld(rule, input))
    const res = await call({ 'x-email': 'nina@x.io', 'x-aal': 'aal1' })
    expect(res.statusCode).toBe(422)
    expect(res.json().secondFactor).toEqual({ rule: 'site_login', requiredAal: 'aal2' })
  })

  it('a policy that predates the rule (no answer) falls back to the gateway decision, never a refusal of its own', async () => {
    h.opa.mockImplementation(async (rule: string, input: Record<string, unknown>) =>
      rule === 'rbac/second_factor_required' ? undefined : opaWorld(rule, input))
    expect((await call({ 'x-email': 'nina@x.io', 'x-aal': 'aal1' })).statusCode).toBe(200)
  })

  it('"forbidden" is left to the route\'s own gate, never turned into a step-up', async () => {
    expect((await call({ 'x-email': 'nobody@x.io', 'x-aal': 'aal1' })).statusCode).toBe(200)
  })

  it('OPA down: the hook steps aside (the route gate answers 503), no 2FA refusal', async () => {
    h.opa.mockRejectedValue(new Error('down'))
    expect((await call({ 'x-email': 'root@x.io', 'x-aal': 'aal1' })).statusCode).toBe(200)
  })

  it('public routes are never judged, so the person can find out what to do', async () => {
    h.session.mockResolvedValue(sessionOf('root@x.io', 'aal1'))
    expect((await call({ 'x-email': 'root@x.io', 'x-aal': 'aal1', cookie: COOKIE }, '/api/public/second-factor')).statusCode).toBe(200)
    expect((await call({ 'x-email': 'root@x.io', 'x-aal': 'aal1' }, '/api/whoami')).statusCode).toBe(200)
  })

  it('a bearer token carries no level: not judged here (it would loop)', async () => {
    expect((await call({ 'x-email': 'root@x.io', 'x-via': 'bearer' })).statusCode).toBe(200)
  })
})

describe('Kratos: which second factors are enrolled', () => {
  const k = new KratosService()
  it('reads the enrolment artefacts, not the credential keys', () => {
    expect(k.mfaMethods({ webauthn: { config: { user_handle: 'x', credentials: [] } } })).toEqual([])
    expect(k.mfaMethods({ totp: { config: { totp_url: 'otpauth://…' } }, lookup_secret: { config: { recovery_codes: [{}] } } })).toEqual(['totp', 'lookup_secret'])
    expect(k.mfaMethods({ webauthn: { config: { credentials: [{ id: 'k' }] } } })).toEqual(['webauthn'])
    // A passkey (passwordless key) is a first factor.
    expect(k.mfaMethods({ webauthn: { config: { credentials: [{ id: 'p', is_passwordless: true }] } } })).toEqual([])
    expect(k.mfaFromCredentials({})).toBe(false)
  })
})
