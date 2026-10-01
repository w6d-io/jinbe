import { CATALOG_V2, ORG_PERMISSIONS_V2, PLATFORM_PERMISSIONS_V2, isV2Permission, scopeOf } from './catalogue.js'
import { ROLES, STAFF_ROLES, type StaffRole } from '../policy/roles.js'

/**
 * jinbe's v2 roles, in code (authz-v2-design §1.1, §2.2, §2.4). Three tables, each explicit:
 *
 *   PLATFORM_ROLES  staff role → platform permissions, bound by the staff groups (same names as v1).
 *                   super_admin is GENERATED: every platform permission. Nothing is special about it
 *                   beyond holding everything; the boot asserts it equals the catalogue.
 *   ORG_ROLES       jinbe's org roles, assigned per person per org (`jinbe:owner` …). owner is
 *                   generated: every org permission.
 *   EVERY_ORG       the ONLY way a platform role acts inside orgs it does not belong to (owner
 *                   decision D1): super_admin all, support members read/write, auditor and security
 *                   read, nobody else.
 *
 * The app these bind under is `jinbe` — there is no `global` scope in v2.
 */

export const JINBE = 'jinbe'

const VIEWER = ['sites:read', 'zones:read', 'gateway:read', 'groups:read', 'orgs:read', 'settings:read', 'stats:read']
const PEOPLE_READ = ['users:read', 'sessions:read', 'access:read', 'audit:read', 'access:check']

export const PLATFORM_ROLES: Readonly<Record<StaffRole, readonly string[]>> = {
  viewer: VIEWER,
  support: [
    ...VIEWER, ...PEOPLE_READ,
    'users:create', 'users:update', 'users:recovery', 'users:verify', 'users:send_login_link',
    'sessions:revoke', 'orgs.members:write',
  ],
  ops: [
    ...VIEWER, 'audit:read', 'access:check',
    'sites:write', 'sites:apply', 'sites:delete', 'sites.requests:approve', 'zones:write', 'zones:delete', 'gateway:apply',
  ],
  developer: [...VIEWER, 'access:check', 'sites:write'],
  auditor: [...VIEWER, ...PEOPLE_READ, 'audit:export', 'policy.bundle:read', 'recert:read'],
  security: [
    ...VIEWER, ...PEOPLE_READ,
    'sessions:revoke', 'users:disable', 'users:update_email', 'users:reset_second_factor', 'users:verify',
    'groups.members:revoke', 'audit:export', 'policy.bundle:read', 'recert:read', 'recert:manage', 'recert:delete',
  ],
  super_admin: PLATFORM_PERMISSIONS_V2,
}

const ORG_READ = ['org.members:read', 'org.keys:read', 'org.audit:read']

export const EVERY_ORG: Readonly<Partial<Record<StaffRole, readonly string[]>>> = {
  super_admin: ORG_PERMISSIONS_V2,
  support: ['org.members:read', 'org.members:write'],
  auditor: ORG_READ,
  security: ORG_READ,
}

export type OrgRole = 'owner' | 'member_manager' | 'key_manager' | 'auditor' | 'viewer'

export const ORG_ROLES: Readonly<Record<OrgRole, { label: string; permissions: readonly string[] }>> = {
  owner: { label: 'Owner: everything in this organisation', permissions: ORG_PERMISSIONS_V2 },
  member_manager: { label: 'Invite and remove members, assign their roles', permissions: ['org.members:read', 'org.members:write'] },
  key_manager: { label: 'API keys and the key policy', permissions: ['org.keys:read', 'org.keys:write', 'org.keys:revoke', 'org.members:read'] },
  auditor: { label: 'Read the audit events and the members', permissions: ['org.audit:read', 'org.members:read'] },
  viewer: { label: 'See members and keys', permissions: ['org.members:read', 'org.keys:read'] },
}

export const ORG_ROLE_NAMES = Object.keys(ORG_ROLES) as OrgRole[]

/** `jinbe:owner` — how an org role is written on the identity (metadata_admin.organization_roles). */
export const qualified = (svc: string, role: string) => `${svc}:${role}`

/** The staff groups and what they bind in v2: the same group names, bound under `jinbe`. */
export function staffGroupsV2(): Record<string, Record<string, string[]>> {
  return Object.fromEntries(STAFF_ROLES.map((r) => [ROLES[r].group, { [JINBE]: [r] }]))
}

export function platformRoleDefinitions(): Record<string, string[]> {
  return Object.fromEntries(STAFF_ROLES.map((r) => [r, [...new Set(PLATFORM_ROLES[r])].sort()]))
}

export function orgRoleDefinitions(): Record<string, string[]> {
  return Object.fromEntries(ORG_ROLE_NAMES.map((r) => [r, [...new Set(ORG_ROLES[r].permissions)].sort()]))
}

export function everyOrgDefinitions(): Record<string, string[]> {
  return Object.fromEntries(
    Object.entries(EVERY_ORG).map(([r, perms]) => [r, [...new Set(perms)].sort()]),
  )
}

/**
 * Boot assertion. Empty when the model is sound:
 *   - every platform role names platform permissions only, every org role and every-org entry org
 *     permissions only, all of them catalogue leaves;
 *   - super_admin holds exactly every platform permission, and (every-org) exactly every org one;
 *   - owner holds exactly every org permission.
 */
export function modelProblems(): string[] {
  const problems: string[] = []
  const check = (where: string, perms: readonly string[], scope: 'platform' | 'org') => {
    for (const p of perms) {
      if (!isV2Permission(p)) problems.push(`${where}: ${p} is not a v2 catalogue permission`)
      else if (scopeOf(p) !== scope) problems.push(`${where}: ${p} is a ${scopeOf(p)} permission, not ${scope}`)
    }
  }
  for (const r of STAFF_ROLES) check(`platform role ${r}`, PLATFORM_ROLES[r], 'platform')
  for (const [r, perms] of Object.entries(EVERY_ORG)) check(`every-org ${r}`, perms ?? [], 'org')
  for (const r of ORG_ROLE_NAMES) check(`org role ${r}`, ORG_ROLES[r].permissions, 'org')

  const same = (a: readonly string[], b: readonly string[]) => [...new Set(a)].sort().join() === [...new Set(b)].sort().join()
  const platform = Object.keys(CATALOG_V2).filter((p) => CATALOG_V2[p].scope === 'platform')
  const org = Object.keys(CATALOG_V2).filter((p) => CATALOG_V2[p].scope === 'org')
  if (!same(PLATFORM_ROLES.super_admin, platform)) problems.push('super_admin does not hold exactly every platform permission')
  if (!same(EVERY_ORG.super_admin ?? [], org)) problems.push('super_admin does not hold exactly every org permission in every org')
  if (!same(ORG_ROLES.owner.permissions, org)) problems.push('org owner does not hold exactly every org permission')
  return problems
}
