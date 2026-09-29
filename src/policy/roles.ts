import { EVERYTHING, isCatalogPermission, type Permission } from './catalog.js'

/**
 * The staff roles, in code (staff-rbac-proposal §2). Written to `roles.global` by the bootstrap on
 * every run and never edited at runtime: nobody can redefine a role they hold. Each lists its
 * permissions explicitly — no inheritance, no ancestors — so the gateway's exact match and this
 * service agree on every one.
 *
 * Each role is bound to one group, `{ global: [<role>] }`. Membership of those groups is the owner's
 * decision per person; the bootstrap creates the groups empty and never moves anybody.
 */

export type StaffRole = 'viewer' | 'support' | 'ops' | 'developer' | 'auditor' | 'security' | 'super_admin'

export interface RoleSpec {
  group: string
  label: string
  permissions: readonly (Permission | typeof EVERYTHING)[]
}

const VIEWER: readonly Permission[] = [
  'sites:read', 'zones:read', 'gateway:read', 'groups:read', 'org:read', 'settings:read', 'stats:read',
]

/** Reading about people: what a desk, an auditor and incident response all need. */
const PEOPLE_READ: readonly Permission[] = [
  'users:read', 'sessions:read', 'access:read', 'org.members:read', 'audit:read', 'access:check',
]

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
      'sessions:revoke', 'org.members:write',
    ],
  },
  ops: {
    group: 'staff-ops',
    label: 'Edge operations: publish sites, zones and the gateway, approve requests',
    permissions: [
      ...VIEWER, 'audit:read', 'access:check',
      'sites:write', 'sites:apply', 'sites:delete', 'sites.requests:approve',
      'zones:write', 'zones:delete', 'gateway:apply', 'org.keys:read', 'org.keys:revoke',
    ],
  },
  developer: {
    group: 'staff-developers',
    label: 'Plug and change sites, import OpenAPI, CI keys for an organisation',
    permissions: [...VIEWER, 'access:check', 'sites:write', 'org.keys:read', 'org.keys:write'],
  },
  auditor: {
    group: 'staff-auditors',
    label: 'Compliance: read everything, export evidence',
    permissions: [...VIEWER, ...PEOPLE_READ, 'org.keys:read', 'audit:export', 'policy.bundle:read', 'recert:read'],
  },
  security: {
    group: 'staff-security',
    label: 'Incident response and access hygiene',
    permissions: [
      ...VIEWER, ...PEOPLE_READ,
      'sessions:revoke', 'users:disable', 'users:update_email', 'users:reset_second_factor', 'users:verify',
      'groups.members:revoke', 'org.keys:read', 'org.keys:revoke',
      'audit:export', 'policy.bundle:read', 'recert:read', 'recert:manage', 'recert:delete',
    ],
  },
  super_admin: {
    group: 'super_admins',
    label: 'Break-glass and owner of the access model (2-3 people)',
    permissions: [EVERYTHING],
  },
}

export const STAFF_ROLES = Object.keys(ROLES) as StaffRole[]

/** `roles.global` as the bootstrap writes it: each staff role and its permissions. */
export function globalRoleDefinitions(): Record<StaffRole, string[]> {
  return Object.fromEntries(STAFF_ROLES.map((r) => [r, [...new Set(ROLES[r].permissions)]])) as Record<StaffRole, string[]>
}

/** Boot assertion: every role permission is a catalogue leaf (or `*` for super_admin alone). */
export function roleProblems(): string[] {
  const problems: string[] = []
  for (const role of STAFF_ROLES) {
    for (const perm of ROLES[role].permissions) {
      if (perm === EVERYTHING ? role !== 'super_admin' : !isCatalogPermission(perm)) {
        problems.push(`role ${role}: ${perm} is not a catalogue permission`)
      }
    }
  }
  return problems
}
