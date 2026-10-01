import { describe, it, expect } from 'vitest'
import { assignableOrgRoles, mayAddToGroup, mayAssignOrgRole, mayDefineGroup, mayScopeKey } from '../../authz-v2/holding.js'
import { orgPermissions, orgsHolding, platformPermissions } from '../../authz-v2/resolve.js'
import { PLATFORM_PERMISSIONS_V2 } from '../../authz-v2/catalogue.js'
import { jinbeData } from './fixtures.js'

const people = {
  'root@x.io': { groups: ['super_admins'] },
  'desk@x.io': { groups: ['staff-support'] },
  'sec@x.io': { groups: ['staff-security'] },
  'ops@x.io': { groups: ['staff-ops'] },
  'owner@acme.io': { organizations: ['acme'], organizationRoles: { acme: ['jinbe:owner'] } },
  'mm@acme.io': { organizations: ['acme'], organizationRoles: { acme: ['jinbe:member_manager'] } },
  'member@acme.io': { organizations: ['acme'] },
}
const d = jinbeData(people)

describe('the holding rule: group membership', () => {
  it('a super admin passes by holding everything, not by a flag', () => {
    expect(platformPermissions(d, 'root@x.io', 'jinbe').sort()).toEqual([...PLATFORM_PERMISSIONS_V2].sort())
    expect(mayAddToGroup(d, 'root@x.io', 'super_admins')).toEqual({ ok: true })
    expect(mayAddToGroup(d, 'root@x.io', 'staff-security')).toEqual({ ok: true })
  })

  it('a super admin missing ONE permission is refused, and told which', () => {
    const narrowed = jinbeData(people)
    narrowed.roles.jinbe.super_admin = narrowed.roles.jinbe.super_admin.filter((p) => p !== 'recert:delete')
    const v = mayAddToGroup(narrowed, 'root@x.io', 'staff-security')
    expect(v).toMatchObject({ ok: false, reason: 'grant_exceeds_own', missing: { platform: { jinbe: ['recert:delete'] } } })
  })

  it('needs the grant permission itself first', () => {
    expect(mayAddToGroup(d, 'desk@x.io', 'staff-viewers')).toMatchObject({ ok: false, reason: 'grant_permission_missing', permission: 'groups.members:write' })
  })

  it('counts what a group carries into every org: holding the platform part is not enough', () => {
    const custom = jinbeData(people)
    // A grant-holder with everything security holds on platform, but no every-org reach.
    custom.roles.jinbe.lead = [...custom.roles.jinbe.security, 'groups.members:write']
    custom.groups.leads = { jinbe: ['lead'] }
    custom.group_membership['lead@x.io'] = ['leads']
    expect(mayAddToGroup(custom, 'lead@x.io', 'staff-security')).toMatchObject({
      ok: false, reason: 'grant_exceeds_own', missing: { platform: {}, everyOrg: { jinbe: ['org.audit:read', 'org.keys:read', 'org.members:read'] } },
    })
  })

  it('refuses a group v2 does not define', () => {
    expect(mayAddToGroup(d, 'root@x.io', 'platform-admins')).toEqual({ ok: false, reason: 'unknown_group' })
  })

  it('code-owned groups are not redefined through the API, whoever asks', () => {
    expect(mayDefineGroup(d, 'root@x.io', 'super_admins', { jinbe: ['viewer'] })).toEqual({ ok: false, reason: 'defined_in_code' })
    expect(mayDefineGroup(d, 'root@x.io', 'staff-viewers', null)).toEqual({ ok: false, reason: 'defined_in_code' })
  })
})

describe('org scope', () => {
  it('org permissions come from roles assigned IN that org; nothing carries to another org', () => {
    expect(orgPermissions(d, 'owner@acme.io', 'acme', 'jinbe')).toContain('org.keys:write')
    expect(orgPermissions(d, 'owner@acme.io', 'globex', 'jinbe')).toEqual([])
    expect(orgPermissions(d, 'member@acme.io', 'acme', 'jinbe')).toEqual([])
  })

  it('a platform role reaches an org only through the every-org map (D1)', () => {
    expect(orgPermissions(d, 'desk@x.io', 'globex', 'jinbe')).toEqual(['org.members:read', 'org.members:write'])
    expect(orgPermissions(d, 'ops@x.io', 'globex', 'jinbe')).toEqual([])
    expect(orgsHolding(d, 'root@x.io', 'org.keys:write', 'jinbe')).toEqual(['acme', 'globex'])
  })

  it('an assignment without membership counts for nothing', () => {
    const stale = jinbeData({ 'gone@acme.io': { organizations: [], organizationRoles: { acme: ['jinbe:owner'] } } })
    expect(orgPermissions(stale, 'gone@acme.io', 'acme', 'jinbe')).toEqual([])
  })
})

describe('the holding rule: org roles', () => {
  it('an owner assigns any jinbe org role to a member', () => {
    expect(assignableOrgRoles(d, 'owner@acme.io', 'acme')).toEqual(
      ['jinbe:auditor', 'jinbe:key_manager', 'jinbe:member_manager', 'jinbe:owner', 'jinbe:viewer'],
    )
  })

  it('a member manager hands out only what they hold there', () => {
    expect(assignableOrgRoles(d, 'mm@acme.io', 'acme')).toEqual(['jinbe:member_manager'])
    expect(mayAssignOrgRole(d, 'mm@acme.io', 'acme', 'jinbe:owner', true)).toMatchObject({ ok: false, reason: 'grant_exceeds_own' })
  })

  it('never to a non-member, never an unknown role, never outside the org the actor holds', () => {
    expect(mayAssignOrgRole(d, 'owner@acme.io', 'acme', 'jinbe:viewer', false)).toEqual({ ok: false, reason: 'not_org_member' })
    expect(mayAssignOrgRole(d, 'owner@acme.io', 'acme', 'jinbe:god', true)).toEqual({ ok: false, reason: 'unknown_role' })
    expect(mayAssignOrgRole(d, 'owner@acme.io', 'globex', 'jinbe:viewer', true)).toMatchObject({ ok: false, reason: 'grant_permission_missing' })
  })

  it('the support desk may assign member roles in any org (every-org), but not owner', () => {
    expect(assignableOrgRoles(d, 'desk@x.io', 'globex')).toEqual(['jinbe:member_manager'])
  })
})

describe('token scopes', () => {
  it('a scope must be held, and never a never-delegable permission', () => {
    expect(mayScopeKey(['users:read', 'users:delete'], ['users:read'])).toMatchObject({ ok: true })
    expect(mayScopeKey(['users:read'], ['users:update'])).toMatchObject({ ok: false, notHeld: ['users:update'] })
    expect(mayScopeKey(['users:delete'], ['users:delete'])).toMatchObject({ ok: false, neverDelegable: ['users:delete'] })
    expect(mayScopeKey(['users:read'], ['*'])).toMatchObject({ ok: false, notHeld: ['*'] })
  })
})
