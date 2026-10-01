import { describe, it, expect } from 'vitest'
import { buildPlan } from '../../authz-v2/plan/review.js'
import { renderPlanMarkdown } from '../../authz-v2/plan/render.js'
import { codeV2Keys } from '../../authz-v2/plan/run.js'
import type { V1Inventory } from '../../authz-v2/plan/inventory.js'
import { globalRoleDefinitions } from '../../policy/roles.js'
import { GENERATED_ROUTE_MAP } from '../../policy/route-map.generated.js'

const ACME = 'acme'

/** A long-lived v1 install: every finding of routing-remap §0 present at once. */
function inventory(): V1Inventory {
  const person = (groups: string[], organizations: string[] = [], organizationRoles: Record<string, string[]> = {}) =>
    ({ id: null, groups: ['users', ...groups], organizations, organizationRoles })
  return {
    services: ['jinbe', 'kuma'],
    roles: {
      global: { ...globalRoleDefinitions(), admin: ['*'] },
      jinbe: { admin: ['*'], org_admin: ['org:manage_users', 'users:read'] },
      kuma: { admin: ['*'], viewer: ['read'] },
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
    },
    groups: {
      'super_admins': { global: ['super_admin'] },
      'platform-admins': { global: ['admin'] },
      'staff-support': { global: ['support'] },
      'staff-ops': { global: ['ops'] },
      'kuma-admin': { kuma: ['admin'] },
      'viewers': { kuma: ['viewer'] },
    },
    systemGroups: ['super_admins'],
    orgAdmins: { [ACME]: ['Boss@Acme.io', 'left@acme.io'] },
    orgServices: { [ACME]: ['kuma'] },
    orgGrants: { [ACME]: { 'grantee@acme.io': ['viewers'] } },
    oathkeeperRuleIds: ['custom-legacy'],
    marker: { schemaVersion: 7, gitSha: 'abc' },
    identities: new Map([
      ['root@x.io', person(['super_admins'])],
      ['padmin@x.io', person(['platform-admins'])],
      ['desk@x.io', person(['staff-support'])],
      ['opsy@x.io', person(['staff-ops'])],
      ['kumaguy@acme.io', person(['kuma-admin'], [ACME])],
      ['boss@acme.io', person([], [ACME], { [ACME]: ['admin'] })],
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
  const plan = buildPlan(inventory(), codeV2Keys(false), NOW)
  const person = (email: string) => plan.people.find((p) => p.email === email)

  it('lists the stale jinbe rows: dead routes (F5) and renames the merge never landed (F4)', () => {
    expect(plan.v1.staleJinbeRows).toEqual([
      { method: 'GET', path: '/api/clusters', permission: 'admin:read', reason: expect.stringContaining('F5') },
      { method: 'PUT', path: '/api/admin/settings/second-factor', permission: 'settings.signin:write', reason: expect.stringContaining('F4') },
    ])
    expect(plan.v1.services.find((s) => s.name === 'global')?.wildcardRoles).toEqual(['admin', 'super_admin'])
    expect(plan.v1.services.find((s) => s.name === 'kuma')?.wildcardRoles).toEqual(['admin'])
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

  it('roster admins lose their org until migrated; the map proposes jinbe:owner for members only', () => {
    expect(person('boss@acme.io')!.losses).toContain(`org.members:write@${ACME}`)
    expect(plan.migration.rosterToOwner).toEqual([{ org: ACME, email: 'boss@acme.io', assign: 'jinbe:owner' }])
    expect(plan.orphans.roster).toContainEqual({ org: ACME, email: 'left@acme.io', member: false })
    expect(plan.migration.orgRoleRenames).toEqual([{ email: 'boss@acme.io', org: ACME, from: 'admin', to: 'jinbe:owner' }])
  })

  it('org grants and retired token scopes are listed with a proposal', () => {
    expect(plan.orphans.orgGrants).toEqual([{ org: ACME, email: 'grantee@acme.io', groups: ['viewers'] }])
    expect(plan.orphans.clients).toEqual([
      expect.objectContaining({ clientId: 'pk-1', retired: ['org:manage_api_keys'], proposed: 'revoke' }),
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
    expect(buildPlan(inventory(), codeV2Keys(false), new Date()).planHash).toBe(plan.planHash)
    const changed = inventory()
    changed.orgAdmins[ACME] = []
    expect(buildPlan(changed, codeV2Keys(false), NOW).planHash).not.toBe(plan.planHash)
  })

  it('renders every section for the owner', () => {
    const md = renderPlanMarkdown(plan)
    for (const h of ['## 1. v1 today', '## 2. Rule by rule', '## 3. People', '## 4. Orphans', '## 5. Migration map']) expect(md).toContain(h)
    expect(md).toContain(plan.planHash)
    expect(md).toContain('| [ ] | jinbe | DELETE | /api/admin/users/:id |')
  })
})
