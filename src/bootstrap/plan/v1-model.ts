import { ORG_PERMISSIONS, PERMISSIONS, PLATFORM_PERMISSIONS, isCatalogPermission, type Permission } from '../../policy/catalog.js'
import { JINBE } from '../../policy/roles.js'
import { buildPolicyData } from '../../authz/model/dataset.js'
import { everyOrgPermissions, orgPermissions, platformPermissions } from '../../authz/model/resolve.js'
import type { Inventory } from './inventory.js'

/**
 * What a person holds in jinbe BEFORE the apply, in today's names so the two sides compare
 * permission by permission.
 *
 * On an install the previous model wrote (marker schema < 8) it is recomputed the way that model's
 * app layer allowed — wider than its gateway on org routes (finding F1):
 *
 *   platform  groups → roles under `global` and `jinbe` → permissions; `*` and the retired aliases
 *             expanded (FROZEN below: the migration must read what the previous release stored)
 *   org X     `*` → every org permission (super_admin, and a service `admin: *` through the org →
 *             service map, F3); a platform holder of an org permission → it in every org; the org's
 *             roster admin who is a member → the org-management set; org grants in X → the roles
 *             those groups bind under X's services
 *
 * On a migrated install it is the current model, resolved like the policy resolves it.
 */

export interface Holdings {
  platform: string[]
  /** org → org permissions; `*` = in every org. */
  org: Record<string, string[]>
}

const sorted = (xs: Iterable<string>) => [...new Set(xs)].sort()

// ── The previous model's names, frozen for the migration ─────────────────────────────────────────
const PREVIOUS_NAME: Readonly<Partial<Record<Permission, string>>> = {
  'orgs:read': 'org:read', 'orgs:write': 'org:write', 'orgs:delete': 'org:delete', 'orgs.owners:write': 'org.admins:write',
}
/** Today's names a previous-model name stands for (platform and org alike). */
const TODAY: Record<string, string[]> = (() => {
  const out: Record<string, string[]> = {}
  for (const p of PERMISSIONS) {
    if (p === 'orgs.members:write' || p === 'org.audit:read') continue
    const old = PREVIOUS_NAME[p] ?? p
    ;(out[old] ??= []).push(p)
  }
  // On a platform route the previous model's org.members:write moved people between orgs.
  out['org.members:write'].push('orgs.members:write')
  return out
})()
const PREVIOUS_LEAVES = Object.keys(TODAY)
const reads = PREVIOUS_LEAVES.filter((n) => n.endsWith(':read'))
const ALIASES: Readonly<Record<string, readonly string[]>> = {
  'admin:read': [...reads.filter((n) => !['org.keys:read', 'policy.bundle:read'].includes(n)), 'audit:export'],
  'admin:write': [
    'users:create', 'users:update', 'users:update_email', 'users.metadata:write', 'users:disable', 'users:delete', 'users:recovery',
    'users:verify', 'users:send_login_link', 'users:reset_second_factor', 'sessions:revoke',
    'access:check', 'groups:write', 'groups.members:write', 'groups.members:revoke',
    'org:write', 'org:delete', 'org.members:write', 'org.admins:write',
    'sites:write', 'settings.signin:write', 'settings.mcp:write',
    'policy.bundle:read', 'policy.bundle:write', 'recert:manage', 'recert:delete',
  ],
  'admin.organisation:read': ['org:read'],
  'admin.organisation:write': ['org:write', 'org:delete'],
  'admin.membership:write': ['groups.members:write', 'groups.members:revoke'],
  'users:assign_group': ['groups.members:write', 'groups.members:revoke'],
  'org:manage_users': ['org.members:read', 'org.members:write'],
  'org:manage_api_keys': ['org.keys:read', 'org.keys:write', 'org.keys:revoke'],
}
/** The previous model's org-admin set (services/org-admin.ts before the apply). */
const ORG_ADMIN = ['org:manage_users', 'org:manage_api_keys', 'users:read', 'users:create']

function previousLeaves(held: readonly string[]): string[] {
  if (held.includes('*')) return PREVIOUS_LEAVES
  return sorted(held.flatMap((h) => (TODAY[h] ? [h] : ALIASES[h] ?? [])))
}

/** Previous-model names held → today's names, platform and org apart. */
function split(held: readonly string[]): { platform: string[]; org: string[] } {
  const today = previousLeaves(held).flatMap((n) => TODAY[n] ?? [])
  return { platform: sorted(today.filter((p) => PLATFORM_PERMISSIONS.includes(p as Permission))), org: sorted(today.filter((p) => ORG_PERMISSIONS.includes(p as Permission))) }
}

function rolePermissions(inv: Inventory, groups: readonly string[], services: readonly string[]): string[] {
  const out: string[] = []
  for (const g of groups) {
    const def = inv.groups[g] ?? {}
    for (const svc of services) for (const role of def[svc] ?? []) out.push(...(inv.roles[svc]?.[role] ?? []))
  }
  return out
}

function previousHoldings(inv: Inventory, email: string): Holdings {
  const facts = inv.identities.get(email)
  const groups = facts?.groups ?? []
  const raw = rolePermissions(inv, groups, ['global', JINBE])
  const { platform, org: everywhere } = split(raw)
  const org: Record<string, string[]> = {}
  if (raw.includes('*')) org['*'] = [...ORG_PERMISSIONS].sort()
  else if (everywhere.length) org['*'] = everywhere
  const lower = email.toLowerCase()
  for (const o of facts?.organizations ?? []) {
    const here: string[] = []
    const services = inv.orgServices[o] ?? []
    const viaServices = rolePermissions(inv, groups, services)
    if (viaServices.includes('*')) here.push(...ORG_PERMISSIONS)
    else here.push(...split(viaServices).org)
    if ((inv.orgAdmins[o] ?? []).some((a) => a.toLowerCase() === lower)) here.push(...split(ORG_ADMIN).org, 'org.audit:read')
    const granted = Object.entries(inv.orgGrants[o] ?? {}).find(([e]) => e.toLowerCase() === lower)?.[1] ?? []
    const viaGrants = rolePermissions(inv, granted, services.length ? services : [JINBE])
    if (viaGrants.includes('*')) here.push(...ORG_PERMISSIONS)
    else here.push(...split(viaGrants).org)
    const all = sorted(here.filter((p) => !(org['*'] ?? []).includes(p)))
    if (all.length) org[o] = all
  }
  return { platform, org }
}

/** What the store holds today, resolved like the policy (a migrated install). */
function currentHoldings(inv: Inventory, email: string): Holdings {
  const d = buildPolicyData(
    { roles: inv.roles, groups: inv.groups, orgRoles: inv.orgRoles, everyOrg: inv.everyOrg, routeMap: {}, orgSites: inv.orgSites },
    inv.identities, inv.orgAssignments, inv.organisations, inv.directGrants,
  )
  return holdingsIn(d, email)
}

/** One person's holdings in a policy document. */
export function holdingsIn(d: ReturnType<typeof buildPolicyData>, email: string): Holdings {
  const org: Record<string, string[]> = {}
  const everyOrg = everyOrgPermissions(d, email, JINBE)
  if (everyOrg.length) org['*'] = everyOrg
  for (const o of Object.keys(d.org_sites)) {
    const here = orgPermissions(d, email, o, JINBE).filter((p) => !everyOrg.includes(p))
    if (here.length) org[o] = here
  }
  return { platform: platformPermissions(d, email, JINBE), org }
}

export function beforeHoldings(inv: Inventory, email: string): Holdings {
  return (inv.marker?.schemaVersion ?? 0) >= 8 ? currentHoldings(inv, email) : previousHoldings(inv, email)
}

/** A previous-model name a scope or role still carries (`*`, an alias, a dead name, a renamed one). */
export function legacyName(name: string): 'wildcard' | 'alias' | 'dead' | 'renamed' | null {
  if (name === '*') return 'wildcard'
  if (Object.prototype.hasOwnProperty.call(ALIASES, name)) return 'alias'
  if (/^admin:(create|update|delete)$/.test(name) || name === 'rbac:write_system' || name === 'read') return 'dead'
  if (!isCatalogPermission(name) && TODAY[name]) return 'renamed'
  return null
}

/** Today's name for a renamed one, or null. */
export function renamedTo(name: string): string | null {
  return legacyName(name) === 'renamed' ? (TODAY[name]?.find((p) => PLATFORM_PERMISSIONS.includes(p as Permission)) ?? null) : null
}
