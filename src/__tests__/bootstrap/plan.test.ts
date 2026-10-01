import { describe, it, expect } from 'vitest'
import { buildPlan } from '../../bootstrap/plan/review.js'
import { renderPlanMarkdown } from '../../bootstrap/plan/render.js'
import type { Inventory } from '../../bootstrap/plan/inventory.js'
import { GENERATED_ROUTE_MAP } from '../../policy/route-map.generated.js'

/** The staff roles as the previous release wrote them in roles.global (frozen, previous names). */
const VIEWER = ['sites:read', 'zones:read', 'gateway:read', 'groups:read', 'org:read', 'settings:read', 'stats:read']
const PEOPLE_READ = ['users:read', 'sessions:read', 'access:read', 'org.members:read', 'audit:read', 'access:check']
const PREVIOUS_STAFF = {
  viewer: VIEWER,
  support: [...VIEWER, ...PEOPLE_READ, 'users:create', 'users:update', 'users:recovery', 'users:verify', 'users:send_login_link', 'sessions:revoke', 'org.members:write'],
  ops: [...VIEWER, 'audit:read', 'access:check', 'sites:write', 'sites:apply', 'sites:delete', 'sites.requests:approve', 'zones:write', 'zones:delete', 'gateway:apply', 'org.keys:read', 'org.keys:revoke'],
  super_admin: ['*'],
}

const ACME = 'acme'

/** A long-lived install of the previous model: every finding of routing-remap §0 present at once. */

function inventory(): Inventory {
  let n = 0
  const person = (groups: string[], organizations: string[] = [], organizationRoles: Record<string, string[]> = {}) =>
    ({ id: `id-${++n}`, groups: ['users', ...groups], organizations, organizationRoles })
  return {
    services: ['jinbe', 'kuma', 'payroll'],
    roles: {
      global: { ...PREVIOUS_STAFF, admin: ['*'] },
      jinbe: { admin: ['*'], org_admin: ['org:manage_users', 'users:read'] },
      kuma: { admin: ['*'], viewer: ['read'] },
      payroll: { editor: ['payroll:write'] },
    },
    routeMaps: {
      jinbe: [
        ...GENERATED_ROUTE_MAP,
        // F5: a route that no longer exists
        { method: 'GET', path: '/api/clusters', permission: 'admin:read' },
        // F4: a rename the additive merge never landed
        { method: 'PUT', path: '/api/admin/settings/second-factor', permission: 'settings.signin:write' },
      ],
      kuma: [],
      payroll: [{ method: 'POST', path: '/runs', permission: 'payroll:write' }],
    },
    groups: {
      'super_admins': { global: ['super_admin'] },
      'platform-admins': { global: ['admin'] },
      'staff-support': { global: ['support'] },
      'staff-ops': { global: ['ops'] },
      'kuma-admin': { kuma: ['admin'] },
      'viewers': { kuma: ['viewer'] },
      'payroll-editors': { payroll: ['editor'] },
    },
    systemGroups: ['super_admins'],
    orgAdmins: { [ACME]: ['Boss@Acme.io', 'left@acme.io'] },
    orgServices: { [ACME]: ['kuma', 'payroll'] },
    orgGrants: { [ACME]: { 'grantee@acme.io': ['viewers', 'payroll-clerks'] } },
    orgSites: {},
    orgRoles: {},
    everyOrg: {},
    orgAssignments: {},
    // grantee@acme.io (id-8) holds users:read directly, until 2999; an expired grant counts for nothing.
    directGrants: {
      'id-8': [
        { id: 'g1', scope: 'platform', app: 'jinbe', kind: 'permission', name: 'users:read', expiresAt: '2999-01-01T00:00:00.000Z', grantedBy: 'root@x.io', grantedAt: '2026-09-01T00:00:00.000Z' },
        { id: 'g2', scope: 'platform', app: 'jinbe', kind: 'permission', name: 'users:delete', expiresAt: '2020-01-01T00:00:00.000Z', grantedBy: 'root@x.io', grantedAt: '2019-09-01T00:00:00.000Z' },
      ],
    },
    sites: ['payroll'],
    // payroll's applied intent, rendered: its editors as a platform group and as an org role.
    siteModels: {
      payroll: {
        roles: { editor: ['payroll:write'], clerk: ['payroll:read'] },
        routeMap: [{ method: 'POST', path: '/runs', permission: 'payroll:write' }, { method: 'GET', path: '/runs', permission: 'payroll:read' }],
        groups: { 'payroll-editors': ['editor'] },
        orgRoles: { clerks: ['payroll:read'] },
        everyOrg: {},
        orgs: [ACME],
      },
    },
    siteFailures: [],
    oathkeeperRuleIds: ['custom-legacy'],
    marker: { schemaVersion: 7, gitSha: 'abc' },
    identities: new Map([
      ['root@x.io', person(['super_admins'])],
      ['padmin@x.io', person(['platform-admins'])],
      ['desk@x.io', person(['staff-support'])],
      ['opsy@x.io', person(['staff-ops'])],
      ['kumaguy@acme.io', person(['kuma-admin'], [ACME])],
      ['boss@acme.io', person([], [ACME], { [ACME]: ['admin'] })],
      ['editor@x.io', person(['payroll-editors'])],
      ['grantee@acme.io', person([], [ACME])],
      ['nobody@x.io', person([])],
    ]),
    organisations: [ACME, 'globex'],
    clients: [
      { clientId: 'pk-1', kind: 'personal', owner: 'u-1', name: null, scopes: ['org:manage_api_keys'] },
      { clientId: 'pk-2', kind: 'personal', owner: 'u-2', name: null, scopes: ['org:read', 'users:read'] },
      { clientId: 'ok-1', kind: 'org', owner: ACME, name: 'ci', scopes: ['payroll:read'] },
    ],
    unavailable: [],
  }
}

const NOW = new Date('2026-10-01T12:00:00Z')

describe('the v2 plan over a v1 inventory', () => {
  const plan = buildPlan(inventory(), NOW)
  const person = (email: string) => plan.people.find((p) => p.email === email)

  it('lists the stale jinbe rows: dead routes (F5) and renames the merge never landed (F4)', () => {
    expect(plan.before.staleJinbeRows).toEqual([
      { method: 'GET', path: '/api/clusters', permission: 'admin:read', reason: expect.stringContaining('F5') },
      { method: 'PUT', path: '/api/admin/settings/second-factor', permission: 'settings.signin:write', reason: expect.stringContaining('F4') },
    ])
    expect(plan.before.services.find((s) => s.name === 'global')?.wildcardRoles).toEqual(['admin', 'super_admin'])
    expect(plan.before.services.find((s) => s.name === 'kuma')?.wildcardRoles).toEqual(['admin'])
  })

  it('super_admin keeps everything: same platform permissions, every org permission in every org', () => {
    expect(person('root@x.io')).toMatchObject({ gains: [], losses: [] })
  })

  it('a second `*` outside super_admins (platform-admins) loses all of it: the group is dropped', () => {
    const p = person('padmin@x.io')!
    expect(p.after.platform).toEqual([])
    expect(p.losses).toContain('users:delete')
    expect(plan.orphans.memberships).toContainEqual({ email: 'padmin@x.io', group: 'platform-admins' })
  })

  it('kuma admin as an org member had org-wide * (F3) and loses it', () => {
    const p = person('kumaguy@acme.io')!
    expect(p.losses).toContain(`org.keys:write@${ACME}`)
    expect(p.after).toEqual({ platform: [], org: {} })
  })

  it('staff roles keep their platform reach; the every-org map decides org reach (D1)', () => {
    expect(person('desk@x.io')!.losses).toEqual([])
    expect(person('opsy@x.io')!.losses.sort()).toEqual(['org.keys:read@*', 'org.keys:revoke@*'])
  })

  it('the D1 losses are shown once per group, first, for the owner to approve', () => {
    expect(plan.lossesByGroup).toContainEqual({ group: 'staff-ops', members: ['opsy@x.io'], losses: ['org.keys:read@*', 'org.keys:revoke@*'], everyOrg: ['org.keys:read@*', 'org.keys:revoke@*'] })
    // A group whose members keep everything is not listed.
    expect(plan.lossesByGroup.map((l) => l.group)).not.toContain('super_admins')
    const md = renderPlanMarkdown(plan)
    expect(md.indexOf('## Losses to approve')).toBeLessThan(md.indexOf('## 1. Today'))
    expect(md).toMatch(/\| staff-ops \| 1 \| org\.keys:read@\*, org\.keys:revoke@\* \|/)
  })

  it('roster admins become jinbe:owner (members only), so they lose nothing in their org', () => {
    expect(plan.migration.orgRoles).toContainEqual({ org: ACME, email: 'boss@acme.io', id: 'id-6', role: 'jinbe:owner', from: 'roster' })
    expect(person('boss@acme.io')!.losses).toEqual([])
    expect(person('boss@acme.io')!.after.org[ACME]).toContain('org.keys:write')
    expect(plan.orphans.roster).toContainEqual({ org: ACME, email: 'left@acme.io', member: false })
    expect(plan.migration.orgRoleRenames).toEqual([{ email: 'boss@acme.io', org: ACME, from: 'admin', to: 'jinbe:owner' }])
  })

  it('site groups and the org entitlements are kept; jinbe and kuma leave the org → service map', () => {
    expect(plan.migration.orgSites).toEqual({ [ACME]: ['payroll'] })
    expect(plan.before.groups.find((g) => g.name === 'payroll-editors')).toMatchObject({ kept: true })
    expect(plan.migration.groups).toContainEqual({ before: 'kuma-admin', after: null })
    expect(plan.migration.groups).toContainEqual({ before: 'super_admins', after: 'super_admins' })
  })

  it("an org grant of a site's org-grantable group becomes that site's org role there (V4)", () => {
    expect(plan.migration.orgRoles).toContainEqual({ org: ACME, email: 'grantee@acme.io', id: 'id-8', role: 'payroll:clerks', from: 'org_grant' })
  })

  it('the after model is what the applied intents render, not what is stored', () => {
    const md = renderPlanMarkdown(plan)
    expect(plan.rules.some((r) => r.service === 'payroll' && r.method === 'GET' && r.path === '/runs')).toBe(true)
    expect(md).not.toContain('## Sites the apply cannot republish')
    const broken = buildPlan({ ...inventory(), siteFailures: [{ site: 'wiki', error: 'applied version 3 is gone' }] }, NOW)
    expect(renderPlanMarkdown(broken)).toContain('| wiki | applied version 3 is gone |')
  })

  it('direct grants are kept by the apply and count after it: in the people diff and the rule holders', () => {
    expect(person('grantee@acme.io')!.after.platform).toEqual(['users:read'])
    expect(person('grantee@acme.io')!.gains).toContain('users:read')
    const row = plan.rules.find((r) => r.service === 'jinbe' && r.permission === 'users:read' && r.method === 'GET')!
    expect(row.holders.emails).toContain('grantee@acme.io')
  })

  it('org grants and retired token scopes are listed with a proposal', () => {
    expect(plan.orphans.orgGrants).toEqual([{ org: ACME, email: 'grantee@acme.io', groups: ['viewers'] }])
    expect(plan.orphans.clients).toEqual([
      expect.objectContaining({ clientId: 'pk-1', retired: ['org:manage_api_keys'], proposed: 'revoke', rescopedTo: [] }),
      expect.objectContaining({ clientId: 'pk-2', retired: ['org:read'], proposed: 'rescope', rescopedTo: ['orgs:read', 'users:read'] }),
    ])
  })

  it('people who hold nothing either way are not listed', () => {
    expect(person('nobody@x.io')).toBeUndefined()
  })

  it('the rule list is the v2 map, each row with the roles, groups and people that reach it', () => {
    const del = plan.rules.find((r) => r.method === 'DELETE' && r.path === '/api/admin/users/:id')!
    expect(del).toMatchObject({ class: 'platform', permission: 'users:delete', roles: ['jinbe:super_admin'], groups: ['super_admins'], stepUp: true, delegable: 'never' })
    expect(del.holders).toEqual({ count: 1, emails: ['root@x.io'] })
    const orgKeys = plan.rules.find((r) => r.method === 'POST' && r.path === '/api/organizations/:organizationId/api-keys')!
    expect(orgKeys.class).toBe('org')
    expect(orgKeys.roles).toEqual(['jinbe:key_manager', 'jinbe:owner', 'jinbe:super_admin (every org)'])
  })

  it('the hash is stable for one state and moves with it', () => {
    expect(buildPlan(inventory(), new Date()).planHash).toBe(plan.planHash)
    const changed = inventory()
    changed.orgAdmins[ACME] = []
    expect(buildPlan(changed, NOW).planHash).not.toBe(plan.planHash)
  })

  it('renders every section for the owner', () => {
    const md = renderPlanMarkdown(plan)
    for (const h of ['## Losses to approve', '## 1. Today', '## 2. Rule by rule', '## 3. People', '## 4. Orphans', '## 5. Migration map']) expect(md).toContain(h)
    expect(md).toContain(plan.planHash)
    expect(md).toContain('| [ ] | jinbe | DELETE | /api/admin/users/:id |')
  })
})
