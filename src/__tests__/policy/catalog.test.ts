import { describe, it, expect } from 'vitest'
import {
  CATALOG, ORG_PERMISSIONS, PERMISSIONS, PLATFORM_PERMISSIONS, catalogPermission, effectivePermissions, grants, scopeGrants, scopeOf,
} from '../../policy/catalog.js'
import {
  EVERY_ORG, ORG_ROLES, ROLES, STAFF_ROLES, everyOrgDefinitions, isStaffGroup, roleDefinitions, roleProblems, staffGroups, staffGroupsRequiringSecondFactor,
} from '../../policy/roles.js'

describe('the catalogue', () => {
  it('names leaves as resource[.sub]:verb, none with a wildcard', () => {
    for (const p of PERMISSIONS) expect(p).toMatch(/^[a-z]+(\.[a-z]+)?:[a-z_]+$/)
  })

  it('scopes every permission platform or org; the org namespace is exactly the design table', () => {
    for (const p of PERMISSIONS) expect(['platform', 'org']).toContain(CATALOG[p].scope)
    expect([...ORG_PERMISSIONS].sort()).toEqual(
      ['org.audit:read', 'org.keys:read', 'org.keys:revoke', 'org.keys:write', 'org.members:read', 'org.members:write'].sort(),
    )
    expect(scopeOf('orgs:read')).toBe('platform')
    expect(scopeOf('org.members:write')).toBe('org')
    expect(scopeOf('nope:x')).toBeUndefined()
  })

  it('the platform permissions about orgs live in orgs:*, so the two namespaces cannot be confused', () => {
    for (const p of PLATFORM_PERMISSIONS) expect(p.startsWith('org.') || p.startsWith('org:'), p).toBe(false)
    expect(PLATFORM_PERMISSIONS).toEqual(expect.arrayContaining(['orgs:read', 'orgs:write', 'orgs:delete', 'orgs.members:write', 'orgs.owners:write']))
  })

  it("what a token may never do is exactly the owner's list", () => {
    const never = PERMISSIONS.filter((p) => CATALOG[p].delegable === 'never').sort()
    expect(never).toEqual([
      'orgs.owners:write', 'policy.bundle:write', 'org.keys:write', 'groups.members:revoke',
      'orgs:delete', 'recert:delete', 'sites:delete', 'users:delete', 'zones:delete',
      'recert:manage', 'sites.requests:approve', 'users:reset_second_factor', 'groups.mfa:write',
      'settings.signin:write', 'settings.mcp:write', 'zones:write', 'gateway:apply', 'policy.bundle:read', 'audit:export',
      'users.grants:write',
      // Org API keys: a machine in an organization is made by a person (staff), never through a token.
      'orgs.keys:write',
      // Site sign-up: exposing a site to the internet and removing people stay with a person.
      'sites.signup:write', 'sites.signup:revoke',
    ].sort())
  })

  it('answers stepUp and delegable per name, undefined outside the catalogue', () => {
    expect(catalogPermission('sites:apply')).toMatchObject({ stepUp: true, delegable: 'direct' })
    expect(catalogPermission('orgs.owners:write')).toMatchObject({ stepUp: true, fourEyes: 'prod', delegable: 'never' })
    expect(catalogPermission('admin:read')).toBeUndefined()
  })
})

describe('grants: exact, nothing else', () => {
  it('a dotted ancestor opens nothing', () => {
    expect(grants(['orgs:write'], 'orgs.owners:write')).toBe(false)
    expect(grants(['groups:write'], 'groups.members:write')).toBe(false)
    expect(grants(['sites:apply'], 'sites.requests:approve')).toBe(false)
  })

  it('there is no wildcard and no alias', () => {
    expect(grants(['*'], 'users:read')).toBe(false)
    expect(grants(['admin:read'], 'users:read')).toBe(false)
    expect(grants(['org:manage_users'], 'org.members:write')).toBe(false)
    expect(grants(['users:read'], 'users:read')).toBe(true)
  })

  it('a scope covers exactly itself; a malformed scope covers nothing', () => {
    expect(scopeGrants(['*'], 'users:read')).toBe(false)
    expect(scopeGrants(['users:read'], 'users:read')).toBe(true)
    expect(scopeGrants(['admin:read'], 'users:read')).toBe(false)
  })

  it('effective permissions are the catalogue names among those held', () => {
    expect(effectivePermissions(['users:read', 'nonsense:x', '*'])).toEqual(['users:read'])
  })
})

describe('the roles in code (authz-v2-design §1.1, §2.2, §2.4)', () => {
  it('are sound: platform roles platform-only, org roles and every-org org-only', () => {
    expect(roleProblems()).toEqual([])
  })

  it('super_admin is generated: exactly every platform permission, and every org permission in every org', () => {
    expect([...ROLES.super_admin.permissions].sort()).toEqual([...PLATFORM_PERMISSIONS].sort())
    expect([...(EVERY_ORG.super_admin ?? [])].sort()).toEqual([...ORG_PERMISSIONS].sort())
    expect([...ORG_ROLES.owner.permissions].sort()).toEqual([...ORG_PERMISSIONS].sort())
  })

  it('every-org: only security reads inside organizations it does not belong to (and super_admin, everything)', () => {
    expect(Object.keys(EVERY_ORG).sort()).toEqual(['security', 'super_admin'])
    expect([...(EVERY_ORG.security ?? [])].sort()).toEqual(['org.audit:read', 'org.keys:read', 'org.members:read'])
  })

  it('each staff role is bound to its own group under jinbe; auditors and viewers are gone', () => {
    expect(Object.keys(staffGroups()).sort()).toEqual(['staff-developers', 'staff-ops', 'staff-security', 'staff-support', 'super_admins'])
    for (const r of STAFF_ROLES) expect(staffGroups()[ROLES[r].group]).toEqual({ jinbe: [r] })
    expect(isStaffGroup('staff-auditors')).toBe(false)
    expect(isStaffGroup('staff-viewers')).toBe(false)
  })

  // The table, pinned (owner decision 2026-10-06): a widening is a visible line here.
  it.each([
    ['developer', ['access:check', 'groups:read', 'orgs.keys:write', 'orgs:read', 'orgs:write', 'sites.members:write', 'sites:read', 'sites:write', 'zones:read']],
    ['support', ['access:check', 'access:read', 'sessions:read', 'sessions:revoke', 'users:create', 'users:read', 'users:recovery', 'users:reset_second_factor', 'users:send_login_link', 'users:update', 'users:verify']],
    ['ops', ['sites.requests:approve', 'sites.signup:revoke', 'sites.signup:write', 'sites:apply', 'sites:read', 'zones:read', 'zones:write']],
    ['security', ['access:check', 'access:read', 'audit:read', 'groups.members:revoke', 'sessions:read', 'sessions:revoke', 'sites.signup:revoke', 'users.grants:read', 'users:disable', 'users:read', 'users:reset_second_factor']],
  ] as const)('%s holds exactly its job', (role, perms) => {
    expect([...ROLES[role].permissions].sort()).toEqual([...perms].sort())
  })

  it('only super admins see settings, the gateway, the bundle, the access model, deletions, recertification and audit export', () => {
    const held = new Set(STAFF_ROLES.filter((r) => r !== 'super_admin').flatMap((r) => [...ROLES[r].permissions]))
    for (const p of ['settings:read', 'settings.signin:write', 'settings.mcp:write', 'gateway:read', 'gateway:apply', 'policy.bundle:read', 'policy.bundle:write',
      'groups:write', 'groups.members:write', 'groups.mfa:write', 'users.grants:write', 'users:delete', 'sites:delete', 'zones:delete', 'orgs:delete',
      'recert:read', 'recert:manage', 'recert:delete', 'audit:export', 'stats:read', 'users:update_email'] as const) expect(held.has(p), p).toBe(false)
  })

  it('no role but super_admin both writes and publishes a site', () => {
    for (const r of STAFF_ROLES.filter((x) => x !== 'super_admin')) {
      const perms = ROLES[r].permissions as readonly string[]
      expect(perms.includes('sites:write') && perms.includes('sites:apply'), r).toBe(false)
    }
  })

  it('a staff group whose role needs a recent second factor always requires one', () => {
    expect([...staffGroupsRequiringSecondFactor()].sort()).toEqual(['staff-developers', 'staff-ops', 'staff-security', 'staff-support', 'super_admins'])
  })

  it('roles.jinbe as the bootstrap writes it', () => {
    const defs = roleDefinitions()
    expect(Object.keys(defs)).toEqual(STAFF_ROLES)
    for (const r of STAFF_ROLES) expect(new Set(defs[r]).size).toBe(defs[r].length)
  })
})
