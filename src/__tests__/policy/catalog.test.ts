import { describe, it, expect } from 'vitest'
import {
  CATALOG, ORG_PERMISSIONS, PERMISSIONS, PLATFORM_PERMISSIONS, catalogPermission, effectivePermissions, grants, scopeGrants, scopeOf,
} from '../../policy/catalog.js'
import {
  EVERY_ORG, ORG_ROLES, ROLES, STAFF_ROLES, everyOrgDefinitions, isStaffGroup, roleDefinitions, roleProblems, staffGroups,
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

  it('every-org is the D1 table: support members r/w, auditor and security read, nobody else', () => {
    expect(everyOrgDefinitions()).toEqual({
      super_admin: [...ORG_PERMISSIONS].sort(),
      support: ['org.members:read', 'org.members:write'],
      auditor: ['org.audit:read', 'org.keys:read', 'org.members:read'],
      security: ['org.audit:read', 'org.keys:read', 'org.members:read'],
    })
  })

  it('each staff role is bound to its own group under jinbe (no global scope)', () => {
    expect(STAFF_ROLES.map((r) => ROLES[r].group)).toEqual([
      'staff-viewers', 'staff-support', 'staff-ops', 'staff-developers', 'staff-auditors', 'staff-security', 'super_admins',
    ])
    for (const [g, def] of Object.entries(staffGroups())) {
      expect(Object.keys(def)).toEqual(['jinbe'])
      expect(isStaffGroup(g)).toBe(true)
    }
    expect(isStaffGroup('platform-admins')).toBe(false)
  })

  it('every staff role reads sites, groups and organisations; support, ops and security the whole platform configuration', () => {
    for (const r of STAFF_ROLES) for (const p of ['sites:read', 'groups:read', 'orgs:read']) expect(grants(ROLES[r].permissions, p), `${r} ${p}`).toBe(true)
    for (const r of ['support', 'ops', 'security'] as const) for (const p of ['zones:read', 'gateway:read', 'settings:read', 'stats:read']) {
      expect(grants(ROLES[r].permissions, p), `${r} ${p}`).toBe(true)
    }
  })

  it('viewer: exactly sites, groups, organisations and the counts; no personal data, no platform configuration', () => {
    expect([...ROLES.viewer.permissions].sort()).toEqual(['groups:read', 'orgs:read', 'sites:read', 'stats:read'])
  })

  it('auditor: people, access and audit evidence plus the directory; no settings, gateway, zones or counts', () => {
    expect([...ROLES.auditor.permissions].sort()).toEqual([
      'access:check', 'access:read', 'audit:export', 'audit:read', 'groups:read', 'orgs:read', 'policy.bundle:read', 'recert:read',
      'sessions:read', 'sites:read', 'users.grants:read', 'users:read',
    ])
    expect(ROLES.auditor.label).toBe('Compliance: people, access and audit evidence')
  })

  it('developer keeps what a site flow needs, without settings:read', () => {
    expect([...ROLES.developer.permissions].sort()).toEqual(['access:check', 'gateway:read', 'groups:read', 'orgs:read', 'sites:read', 'sites:write', 'stats:read', 'zones:read'])
  })

  it.each([
    ['support', ['users:reset_second_factor', 'users:update_email', 'users:delete', 'users:disable', 'groups.members:write', 'sites:write', 'settings.signin:write']],
    ['ops', ['users:read', 'users:update', 'groups:write', 'groups.members:write', 'settings.signin:write', 'policy.bundle:write']],
    ['developer', ['sites:apply', 'sites.requests:approve', 'zones:write', 'gateway:apply', 'users:read']],
    ['auditor', ['users:update', 'sites:write', 'groups.members:revoke', 'recert:manage', 'sessions:revoke']],
    ['security', ['groups.members:write', 'groups:write', 'sites:write', 'sites:apply', 'settings.signin:write', 'users:recovery', 'users:send_login_link', 'users:delete']],
  ] as const)('%s explicitly cannot', (role, denied) => {
    for (const p of denied) expect(grants(ROLES[role].permissions, p), `${role} ${p}`).toBe(false)
  })

  it('what no other staff role holds, only super_admin does', () => {
    const held = new Set(STAFF_ROLES.filter((r) => r !== 'super_admin').flatMap((r) => [...ROLES[r].permissions]))
    expect(PLATFORM_PERMISSIONS.filter((p) => !held.has(p)).sort()).toEqual([
      'groups.members:write', 'groups.mfa:write', 'groups:write', 'orgs.owners:write', 'orgs:delete', 'orgs:write', 'policy.bundle:write',
      'settings.mcp:write', 'settings.signin:write', 'users.grants:write', 'users.metadata:write', 'users:delete',
    ].sort())
  })

  it('roles.jinbe as the bootstrap writes it', () => {
    const defs = roleDefinitions()
    expect(Object.keys(defs)).toEqual(STAFF_ROLES)
    for (const r of STAFF_ROLES) expect(new Set(defs[r]).size).toBe(defs[r].length)
  })
})
