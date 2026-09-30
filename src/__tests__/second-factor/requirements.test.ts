import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import { installRouteAccess } from '../../policy/route-access.js'

// Every 2FA requirement said where it applies: groups, permissions, sites, one person, the refusals,
// and GET /api/admin/rbac/second-factor-map (the console's badges and the MCP read it).

const h = vi.hoisted(() => ({
  config: {} as Record<string, string>,
  groups: {
    super_admins: { global: ['super_admin'] },
    staff_ops: { global: ['ops'] },
    readers: { jinbe: ['viewer'] },
  } as Record<string, Record<string, string[]>>,
  groupsFail: false,
  records: [] as unknown[],
  versions: {} as Record<string, unknown>,
}))

vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getConfig: vi.fn(async () => ({ ...h.config })),
    getGroups: vi.fn(async () => {
      if (h.groupsFail) throw new Error('ECONNREFUSED')
      return h.groups
    }),
  },
}))
vi.mock('../../sites/repository.js', () => ({
  sitesRepository: {
    list: vi.fn(async () => h.records),
    version: vi.fn(async (name: string, v: number) => h.versions[`${name}@${v}`] ?? null),
  },
}))
vi.mock('../../services/rbac.service.js', () => ({
  rbacService: { getGroups: vi.fn(async () => ({ groups: Object.entries(h.groups).map(([name, services]) => ({ name, services })) })) },
}))
vi.mock('../../services/opal-publisher.js', () => ({ opalPublisher: { schedule: vi.fn() } }))
vi.mock('../../middleware/require-permission.js', async () => (await import('../helpers/permission-stand-ins.js')).permissionStandIn({ readsOpen: false }))
vi.mock('../../middleware/require-admin.js', async () => (await import('../helpers/permission-stand-ins.js')).adminStandIn())

import {
  groupSecondFactor, secondFactorRefusal, siteSecondFactor, stepUpPermissionsOf, stepUpRule, userSecondFactor,
} from '../../second-factor/requirements.js'
import { secondFactorMapRoutes } from '../../second-factor/routes.js'
import { resetSecondFactorSettingsCache } from '../../second-factor/settings.js'
import { catalogRoutes } from '../../routes/catalog.routes.js'
import { rbacController } from '../../controllers/rbac.controller.js'
import { groupJsonSchema } from '../../schemas/rbac/index.js'

describe('groups', () => {
  it('required by the default (no setting saved), by the setting, or not at all', () => {
    const def = { groups: ['super_admins'], explicit: false }
    expect(groupSecondFactor('super_admins', h.groups.super_admins, def)).toEqual({ required: true, source: 'default', enrolBeforeJoining: true })
    expect(groupSecondFactor('super_admins', h.groups.super_admins, { ...def, explicit: true }).source).toBe('setting')
    expect(groupSecondFactor('readers', h.groups.readers, def)).toEqual({ required: false, source: null, enrolBeforeJoining: false })
  })

  it('a group with a global role needs its new members enrolled, even when sign-in does not ask them', () => {
    expect(groupSecondFactor('staff_ops', h.groups.staff_ops, { groups: [], explicit: true })).toEqual({ required: false, source: null, enrolBeforeJoining: true })
  })
})

describe('permissions', () => {
  it('a step-up permission says how recent, whether a personal key may stand in, and four-eyes', () => {
    expect(stepUpRule('groups:write')).toEqual({ required: true, maxAgeMin: 15, viaPersonalKey: { maxAgeDays: 30 }, fourEyes: 'prod' })
    expect(stepUpRule('users:delete')).toEqual({ required: true, maxAgeMin: 15, viaPersonalKey: null, fourEyes: false })
    expect(stepUpRule('sites:read')).toEqual({ required: false, maxAgeMin: null, viaPersonalKey: null, fourEyes: false })
    expect(stepUpRule('not:real')).toBeNull()
  })

  it('which held permissions need a recent second factor (aliases and * resolved)', () => {
    expect(stepUpPermissionsOf(['sites:read', 'sites:apply'])).toEqual(['sites:apply'])
    expect(stepUpPermissionsOf(['*'])).toContain('settings.signin:write')
  })
})

describe('sites', () => {
  const site = (twoFactor?: object) => ({ login: twoFactor ? { twoFactor, reach: 'granted' as const } : undefined }) as never

  it('says the bar in plain words', () => {
    expect(siteSecondFactor(site())).toMatchObject({ scope: 'none', minAal: 'aal1', clients: null })
    expect(siteSecondFactor(site({ scope: 'all', clients: 'exempt' }))).toMatchObject({ scope: 'all', minAal: 'aal2', summary: 'Two-step sign-in on every signed-in request.' })
    expect(siteSecondFactor(site({ scope: 'writes', routes: ['export'], clients: 'refused' })).summary)
      .toBe('Two-step sign-in for changes (POST, PUT, PATCH, DELETE) and on 1 chosen route; reading works after a password. OAuth clients are refused where it applies.')
    expect(siteSecondFactor(site({ scope: 'none', routes: ['a', 'b'], clients: 'exempt' }))).toMatchObject({ minAal: 'aal2', routes: ['a', 'b'], summary: 'Two-step sign-in on 2 chosen routes only.' })
  })
})

describe('one person', () => {
  const now = Date.parse('2026-09-30T12:00:00Z')

  it('the caller: required because of which groups, session level, factor age, fresh or not', () => {
    const out = userSecondFactor({
      groups: ['readers', 'super_admins'], permissions: ['sites:apply', 'sites:read'],
      setting: { groups: ['super_admins'], explicit: false }, methods: null,
      session: { aal: 'aal2', secondFactorAt: '2026-09-30T11:50:00Z', authVia: 'session' }, now,
    })
    expect(out).toEqual({
      required: true, requiredBecause: ['super_admins'], enrolled: true, methods: null,
      currentAal: 'aal2', factorAgeMin: 10, stepUpFresh: true, stepUpPermissions: ['sites:apply'],
    })
  })

  it('a stale factor is not fresh; an aal1 session has no factor age', () => {
    const stale = userSecondFactor({ groups: [], permissions: [], setting: { groups: [], explicit: true }, methods: ['totp'], session: { aal: 'aal2', secondFactorAt: '2026-09-30T11:00:00Z' }, now })
    expect(stale).toMatchObject({ required: false, enrolled: true, factorAgeMin: 60, stepUpFresh: false })
    const aal1 = userSecondFactor({ groups: [], permissions: [], setting: { groups: [], explicit: true }, methods: [], session: { aal: 'aal1', authVia: 'session' }, now })
    expect(aal1).toMatchObject({ enrolled: false, currentAal: 'aal1', factorAgeMin: null, stepUpFresh: false })
  })
})

describe('refusal fields', () => {
  it('carry the rule, the permission and what satisfies it', () => {
    expect(secondFactorRefusal('step_up', { permission: 'sites:apply' })).toEqual({ permission: 'sites:apply', secondFactor: { rule: 'step_up', requiredAal: 'aal2', maxAgeMin: 15 } })
    expect(secondFactorRefusal('enrol_before_joining', { groups: ['staff_ops'] })).toEqual({ secondFactor: { rule: 'enrol_before_joining', requiredAal: 'aal2', groups: ['staff_ops'] } })
  })
})

describe('GET /api/admin/rbac/second-factor-map', () => {
  let app: FastifyInstance
  beforeAll(async () => {
    app = Fastify()
    installRouteAccess(app)
    app.addHook('onRequest', async (request) => {
      request.userContext = { email: 'ann@x.io', id: 'id-ann', name: 'Ann', authVia: 'session' } as never
    })
    await app.register(secondFactorMapRoutes, { prefix: '/api/admin/rbac' })
    await app.register(catalogRoutes, { prefix: '/api' })
    app.get('/api/admin/rbac/groups', {
      config: { permission: 'groups:read' },
      schema: { response: { 200: { type: 'object', properties: { groups: { type: 'array', items: groupJsonSchema } } } } },
    }, rbacController.getGroups.bind(rbacController))
    await app.ready()
  })
  afterAll(() => app.close())
  beforeEach(() => {
    h.config = {}
    h.groupsFail = false
    h.records = [
      { site: { name: 'payroll', displayName: 'Payroll', address: { host: 'payroll.x.io' }, login: { twoFactor: { scope: 'none', clients: 'exempt' }, reach: 'granted' } }, applied: { version: 2 } },
      { site: { name: 'wiki', displayName: 'Wiki', address: { host: 'wiki.x.io' } } },
    ]
    // The applied version asks for more than the saved one: the map shows what visitors meet.
    h.versions = { 'payroll@2': { site: { login: { twoFactor: { scope: 'writes', clients: 'exempt' }, reach: 'granted' } } } }
    resetSecondFactorSettingsCache()
  })
  const get = (perms: string) => app.inject({ url: '/api/admin/rbac/second-factor-map', headers: { 'x-test-perms': perms } })

  it('with groups:read and sites:read: every section', async () => {
    const res = await get('groups:read,sites:read')
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.rules.map((r: { id: string }) => r.id)).toEqual(['group_sign_in', 'step_up', 'enrol_before_joining', 'site_login', 'personal_key', 'oauth_grant'])
    expect(body.limits).toEqual({ stepUpMaxAgeMin: 15, personalKeyMaxAgeDays: 30, oauthGrantMaxAgeHours: 12 })
    expect(body.signIn).toEqual({ groups: ['super_admins'], explicit: false, defaultGroups: ['super_admins'] })
    expect(body.groups).toEqual([
      { name: 'readers', secondFactor: { required: false, source: null, enrolBeforeJoining: false } },
      { name: 'staff_ops', secondFactor: { required: false, source: null, enrolBeforeJoining: true } },
      { name: 'super_admins', secondFactor: { required: true, source: 'default', enrolBeforeJoining: true } },
    ])
    expect(body.permissions.find((p: { name: string }) => p.name === 'sites:apply').stepUpRule).toEqual({ required: true, maxAgeMin: 15, viaPersonalKey: { maxAgeDays: 30 }, fourEyes: 'prod' })
    expect(body.roles.find((r: { name: string }) => r.name === 'ops').stepUpPermissions).toContain('gateway:apply')
    expect(body.sites).toEqual([
      expect.objectContaining({ name: 'payroll', applied: true, secondFactor: expect.objectContaining({ scope: 'writes', minAal: 'aal2' }) }),
      expect.objectContaining({ name: 'wiki', applied: false, secondFactor: expect.objectContaining({ scope: 'none', minAal: 'aal1' }) }),
    ])
    expect(body.organizations.rules).toEqual([])
    expect(body.unavailable).toEqual([])
  })

  it('sites:read alone is enough; the groups are not shown', async () => {
    const body = (await get('sites:read')).json()
    expect(body.groups).toBeNull()
    expect(body.sites).toHaveLength(2)
  })

  it('groups:read alone: no sites', async () => {
    const body = (await get('groups:read')).json()
    expect(body.sites).toBeNull()
    expect(body.groups).toHaveLength(3)
  })

  it('neither: 403', async () => {
    expect((await get('users:read')).statusCode).toBe(403)
  })

  it('a saved setting is its source; an unreadable section is null and named, never an empty list', async () => {
    h.config = { second_factor_groups: JSON.stringify(['staff_ops']) }
    let body = (await get('groups:read')).json()
    expect(body.groups.find((g: { name: string }) => g.name === 'staff_ops').secondFactor).toEqual({ required: true, source: 'setting', enrolBeforeJoining: true })
    resetSecondFactorSettingsCache()
    h.groupsFail = true
    body = (await get('groups:read')).json()
    expect(body.groups).toBeNull()
    expect(body.unavailable).toEqual(['groups'])
  })

  it('/api/catalog carries each permission\'s rule and each role\'s step-up permissions', async () => {
    const body = (await app.inject({ url: '/api/catalog' })).json()
    expect(body.permissions.find((p: { name: string }) => p.name === 'groups:write')).toMatchObject({ stepUp: true, stepUpRule: { required: true, maxAgeMin: 15, viaPersonalKey: { maxAgeDays: 30 } } })
    expect(body.roles.find((r: { name: string }) => r.name === 'viewer').stepUpPermissions).toEqual([])
  })

  it('the groups list badges each group (and survives the serializer)', async () => {
    const body = (await app.inject({ url: '/api/admin/rbac/groups', headers: { 'x-test-perms': 'groups:read' } })).json()
    expect(body.groups.find((g: { name: string }) => g.name === 'super_admins')).toEqual({
      name: 'super_admins', services: { global: ['super_admin'] }, secondFactor: { required: true, source: 'default', enrolBeforeJoining: true },
    })
  })
})
