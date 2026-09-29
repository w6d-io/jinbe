import { describe, it, expect } from 'vitest'
import { ALIASES, CATALOG, PERMISSIONS, catalogPermission, effectivePermissions, grants, isCatalogPermission, scopeGrants } from '../../policy/catalog.js'
import { ROLES, STAFF_ROLES, globalRoleDefinitions, roleProblems } from '../../policy/roles.js'

describe('the catalogue', () => {
  it('names leaves as resource[.sub]:verb', () => {
    for (const p of PERMISSIONS) expect(p).toMatch(/^[a-z]+(\.[a-z]+)?:[a-z_]+$/)
  })

  it('every alias stands for catalogue leaves only, and no alias is itself a leaf', () => {
    for (const [name, leaves] of Object.entries(ALIASES)) {
      expect(isCatalogPermission(name), name).toBe(false)
      for (const leaf of leaves) expect(isCatalogPermission(leaf), `${name} → ${leaf}`).toBe(true)
    }
  })

  it("what a token may never do is exactly the owner's list (2026-09-29)", () => {
    const never = PERMISSIONS.filter((p) => CATALOG[p].delegable === 'never').sort()
    expect(never).toEqual([
      // the access model itself
      'groups:write', 'org.admins:write', 'policy.bundle:write',
      // key and client creation (and revocation, a deletion)
      'org.keys:revoke', 'org.keys:write',
      // deletions
      'org:delete', 'recert:delete', 'sites:delete', 'users:delete', 'zones:delete',
      // approvals (a campaign close applies its revokes)
      'recert:manage', 'sites.requests:approve',
      // second-factor reset
      'users:reset_second_factor',
      // tightened by the lead (2026-09-29): sign-in and MCP settings, the edge, bulk exports
      'settings.signin:write', 'settings.mcp:write', 'zones:write', 'gateway:apply', 'policy.bundle:read', 'audit:export',
    ].sort())
  })
})

describe('catalogPermission', () => {
  it('answers stepUp and delegable per name, undefined outside the catalogue', () => {
    expect(catalogPermission('sites:apply')).toMatchObject({ stepUp: true, delegable: 'direct' })
    expect(catalogPermission('users:delete')).toMatchObject({ stepUp: true, delegable: 'never' })
    expect(catalogPermission('users:read')).toMatchObject({ stepUp: false, delegable: 'direct' })
    expect(catalogPermission('admin:read')).toBeUndefined()
  })
})

describe('grants', () => {
  it('matches exactly: a dotted ancestor opens nothing, as at the gateway', () => {
    expect(grants(['org:write'], 'org.admins:write')).toBe(false)
    expect(grants(['groups:write'], 'groups.members:write')).toBe(false)
    expect(grants(['org:read'], 'org.keys:read')).toBe(false)
    expect(grants(['sites:apply'], 'sites.requests:approve')).toBe(false)
  })

  it('the wildcard is everything, and nothing but the wildcard is the wildcard', () => {
    expect(grants(['*'], 'users:reset_second_factor')).toBe(true)
    expect(grants(['*'], '*')).toBe(true)
    expect(grants(['admin:write'], '*')).toBe(false)
  })

  it('honours the legacy names for one release: admin:read reads, admin:write writes, neither applies', () => {
    expect(grants(['admin:read'], 'users:read')).toBe(true)
    expect(grants(['admin:read'], 'users:delete')).toBe(false)
    expect(grants(['admin:write'], 'groups:write')).toBe(true)
    expect(grants(['admin:write'], 'users:read')).toBe(false)
    for (const p of ['sites:apply', 'sites:delete', 'sites.requests:approve', 'zones:write', 'gateway:apply', 'org.keys:write']) {
      expect(grants(['admin:read', 'admin:write'], p), p).toBe(false)
    }
    expect(grants(['org:manage_users'], 'org.members:write')).toBe(true)
    expect(grants(['org:manage_api_keys'], 'org.keys:revoke')).toBe(true)
  })

  it("a name outside the catalogue (a site's own permission) keeps its model's ancestor rule", () => {
    expect(grants(['payroll:read'], 'payroll.runs:read')).toBe(true)
    expect(grants(['payroll.run:read'], 'payroll.runs:read')).toBe(false)
  })

  it('a scope never carries the wildcard', () => {
    expect(scopeGrants(['*'], 'users:read')).toBe(false)
    expect(scopeGrants(['users:read'], 'users:read')).toBe(true)
    expect(scopeGrants(['admin:read'], 'users:read')).toBe(true)
  })

  it('effective permissions are the leaves a set of held names amounts to', () => {
    expect(effectivePermissions(['*'])).toEqual(PERMISSIONS)
    expect(effectivePermissions(['users:read', 'nonsense:x'])).toEqual(['users:read'])
    expect(effectivePermissions(['admin.organisation:write'])).toEqual(['org:write', 'org:delete'])
  })
})

describe('the staff roles (staff-rbac-proposal §2)', () => {
  it('list catalogue leaves only; only super_admin holds `*`', () => {
    expect(roleProblems()).toEqual([])
    expect(ROLES.super_admin.permissions).toEqual(['*'])
    for (const r of STAFF_ROLES.filter((x) => x !== 'super_admin')) expect(ROLES[r].permissions).not.toContain('*')
  })

  it('each is bound to its own group', () => {
    expect(STAFF_ROLES.map((r) => ROLES[r].group)).toEqual([
      'staff-viewers', 'staff-support', 'staff-ops', 'staff-developers', 'staff-auditors', 'staff-security', 'super_admins',
    ])
  })

  it('every staff role reads the platform surfaces; viewer reads no personal data', () => {
    for (const r of STAFF_ROLES) for (const p of ['sites:read', 'zones:read', 'gateway:read', 'groups:read', 'org:read', 'settings:read', 'stats:read']) {
      expect(grants(ROLES[r].permissions, p), `${r} ${p}`).toBe(true)
    }
    for (const p of ['users:read', 'sessions:read', 'audit:read', 'access:read']) expect(grants(ROLES.viewer.permissions, p)).toBe(false)
  })

  it.each([
    ['support', ['users:reset_second_factor', 'users:update_email', 'users:delete', 'users:disable', 'groups.members:write', 'sites:write', 'org.keys:read', 'settings.signin:write']],
    ['ops', ['users:read', 'users:update', 'groups:write', 'groups.members:write', 'settings.signin:write', 'policy.bundle:write']],
    ['developer', ['sites:apply', 'sites.requests:approve', 'zones:write', 'gateway:apply', 'users:read']],
    ['auditor', ['users:update', 'sites:write', 'groups.members:revoke', 'recert:manage', 'sessions:revoke']],
    ['security', ['groups.members:write', 'groups:write', 'sites:write', 'sites:apply', 'settings.signin:write', 'users:recovery', 'users:send_login_link', 'users:delete']],
  ] as const)('%s explicitly cannot', (role, denied) => {
    for (const p of denied) expect(grants(ROLES[role].permissions, p), `${role} ${p}`).toBe(false)
  })

  it('what no staff role holds, only super_admin does', () => {
    const held = new Set(STAFF_ROLES.filter((r) => r !== 'super_admin').flatMap((r) => [...ROLES[r].permissions]))
    expect(PERMISSIONS.filter((p) => !held.has(p)).sort()).toEqual([
      'groups.members:write', 'groups:write', 'org.admins:write', 'org:delete', 'org:write', 'policy.bundle:write',
      'settings.mcp:write', 'settings.signin:write', 'users.metadata:write', 'users:delete',
    ].sort())
  })

  it('roles.global as the bootstrap writes it', () => {
    const defs = globalRoleDefinitions()
    expect(Object.keys(defs)).toEqual(STAFF_ROLES)
    for (const r of STAFF_ROLES) expect(new Set(defs[r]).size).toBe(defs[r].length)
  })
})
