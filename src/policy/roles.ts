import { ORG_PERMISSIONS, PLATFORM_PERMISSIONS, isCatalogPermission, scopeOf, type Permission } from './catalog.js'

/**
 * jinbe's roles, in code (authz-v2-design §1.1, §2.2, §2.4). Written by the bootstrap on every run and
 * never edited at runtime: nobody can redefine a role they hold. Three tables, each explicit — no
 * wildcard, no inheritance, no ancestors — so the gateway's exact match and this service agree:
 *
 *   ROLES       staff role → platform permissions, each bound by one staff group under the app
 *               `jinbe` (`{ jinbe: [<role>] }`). super_admin is GENERATED: every platform permission.
 *               Nothing is special about it beyond holding everything; the boot asserts it equals
 *               the catalogue, so a new permission joins it in the same commit.
 *   EVERY_ORG   the ONLY way a platform role acts inside orgs it does not belong to (owner decision
 *               D1): super_admin all, support members read/write, auditor and security read.
 *   ORG_ROLES   jinbe's org roles, assigned per person per org (`jinbe:owner` …, org-roles store).
 *               owner is generated: every org permission.
 *
 * Membership of the staff groups is the owner's decision per person; the bootstrap never moves anybody.
 */

export const JINBE = 'jinbe'

export type StaffRole = 'viewer' | 'support' | 'ops' | 'developer' | 'auditor' | 'security' | 'super_admin'

export interface RoleSpec {
  group: string
  label: string
  permissions: readonly Permission[]
}

const VIEWER: readonly Permission[] = [
  'sites:read', 'zones:read', 'gateway:read', 'groups:read', 'orgs:read', 'settings:read', 'stats:read',
]

/** Reading about people: what a desk, an auditor and incident response all need. */
const PEOPLE_READ: readonly Permission[] = ['users:read', 'sessions:read', 'access:read', 'audit:read', 'access:check']

export const ROLES: Readonly<Record<StaffRole, RoleSpec>> = {
  viewer: {
    group: 'staff-viewers',
    label: 'Read-only staff: sites, zones, gateway, groups, organisations, settings. No personal data',
    permissions: VIEWER,
  },
  support: {
    group: 'staff-support',
    label: 'Support desk: find the person, fix sign-in, manage organisation members',
    permissions: [
      ...VIEWER, ...PEOPLE_READ,
      'users:create', 'users:update', 'users:recovery', 'users:verify', 'users:send_login_link',
      'sessions:revoke', 'orgs.members:write',
    ],
  },
  ops: {
    group: 'staff-ops',
    label: 'Edge operations: publish sites, zones and the gateway, approve requests',
    permissions: [
      ...VIEWER, 'audit:read', 'access:check',
      'sites:write', 'sites:apply', 'sites:delete', 'sites.requests:approve',
      'zones:write', 'zones:delete', 'gateway:apply',
    ],
  },
  developer: {
    group: 'staff-developers',
    label: 'Plug and change sites, import OpenAPI',
    permissions: [...VIEWER, 'access:check', 'sites:write'],
  },
  auditor: {
    group: 'staff-auditors',
    label: 'Compliance: read everything, export evidence',
    permissions: [...VIEWER, ...PEOPLE_READ, 'audit:export', 'policy.bundle:read', 'recert:read', 'users.grants:read'],
  },
  security: {
    group: 'staff-security',
    label: 'Incident response and access hygiene',
    permissions: [
      ...VIEWER, ...PEOPLE_READ,
      'sessions:revoke', 'users:disable', 'users:update_email', 'users:reset_second_factor', 'users:verify',
      'groups.members:revoke', 'audit:export', 'policy.bundle:read', 'recert:read', 'recert:manage', 'recert:delete',
      'users.grants:read',
    ],
  },
  super_admin: {
    group: 'super_admins',
    label: 'Break-glass and owner of the access model (2-3 people): every platform permission',
    permissions: PLATFORM_PERMISSIONS,
  },
}

export const STAFF_ROLES = Object.keys(ROLES) as StaffRole[]

const ORG_READ: readonly Permission[] = ['org.members:read', 'org.keys:read', 'org.audit:read']

export const EVERY_ORG: Readonly<Partial<Record<StaffRole, readonly Permission[]>>> = {
  super_admin: ORG_PERMISSIONS,
  support: ['org.members:read', 'org.members:write'],
  auditor: ORG_READ,
  security: ORG_READ,
}

export type OrgRole = 'owner' | 'member_manager' | 'key_manager' | 'auditor' | 'viewer'

export const ORG_ROLES: Readonly<Record<OrgRole, { label: string; permissions: readonly Permission[] }>> = {
  owner: { label: 'Owner: everything in this organisation', permissions: ORG_PERMISSIONS },
  member_manager: { label: 'Invite and remove members, assign their roles', permissions: ['org.members:read', 'org.members:write'] },
  key_manager: { label: 'API keys and the key policy', permissions: ['org.keys:read', 'org.keys:write', 'org.keys:revoke', 'org.members:read'] },
  auditor: { label: 'Read the audit events and the members', permissions: ['org.audit:read', 'org.members:read'] },
  viewer: { label: 'See members and keys', permissions: ['org.members:read', 'org.keys:read'] },
}

export const ORG_ROLE_NAMES = Object.keys(ORG_ROLES) as OrgRole[]

/** `jinbe:owner` — how an org role assignment names its role. */
export const qualified = (svc: string, role: string) => `${svc}:${role}`

const sortedSet = (xs: readonly string[]) => [...new Set(xs)].sort()

/** `roles.jinbe` as the bootstrap writes it: each staff role and its permissions. */
export function roleDefinitions(): Record<StaffRole, string[]> {
  return Object.fromEntries(STAFF_ROLES.map((r) => [r, sortedSet(ROLES[r].permissions)])) as Record<StaffRole, string[]>
}

/** The staff groups and what they bind: `{ group: { jinbe: [role] } }`. */
export function staffGroups(): Record<string, Record<string, string[]>> {
  return Object.fromEntries(STAFF_ROLES.map((r) => [ROLES[r].group, { [JINBE]: [r] }]))
}

export function orgRoleDefinitions(): Record<string, string[]> {
  return Object.fromEntries(ORG_ROLE_NAMES.map((r) => [r, sortedSet(ORG_ROLES[r].permissions)]))
}

export function everyOrgDefinitions(): Record<string, string[]> {
  return Object.fromEntries(Object.entries(EVERY_ORG).map(([r, perms]) => [r, sortedSet(perms ?? [])]))
}

/** Whether a group is one of the staff groups code defines (not editable through the API). */
export function isStaffGroup(name: string): boolean {
  return STAFF_ROLES.some((r) => ROLES[r].group === name)
}

/**
 * Boot assertion, empty when the model is sound: platform roles name platform permissions only,
 * org roles and every-org entries org permissions only, all of them catalogue leaves; super_admin
 * holds exactly every platform permission and (every-org) every org one; owner every org one.
 */
export function roleProblems(): string[] {
  const problems: string[] = []
  const check = (where: string, perms: readonly string[], scope: 'platform' | 'org') => {
    for (const p of perms) {
      if (!isCatalogPermission(p)) problems.push(`${where}: ${p} is not a catalogue permission`)
      else if (scopeOf(p) !== scope) problems.push(`${where}: ${p} is a ${scopeOf(p)} permission, not ${scope}`)
    }
  }
  for (const r of STAFF_ROLES) check(`role ${r}`, ROLES[r].permissions, 'platform')
  for (const [r, perms] of Object.entries(EVERY_ORG)) check(`every-org ${r}`, perms ?? [], 'org')
  for (const r of ORG_ROLE_NAMES) check(`org role ${r}`, ORG_ROLES[r].permissions, 'org')
  const same = (a: readonly string[], b: readonly string[]) => sortedSet(a).join() === sortedSet(b).join()
  if (!same(ROLES.super_admin.permissions, PLATFORM_PERMISSIONS)) problems.push('super_admin does not hold exactly every platform permission')
  if (!same(EVERY_ORG.super_admin ?? [], ORG_PERMISSIONS)) problems.push('super_admin does not hold exactly every org permission in every org')
  if (!same(ORG_ROLES.owner.permissions, ORG_PERMISSIONS)) problems.push('org owner does not hold exactly every org permission')
  return problems
}
