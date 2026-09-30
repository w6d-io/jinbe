import { ALIASES, EVERYTHING, grants } from '../policy/catalog.js'
import { ROLES, STAFF_ROLES } from '../policy/roles.js'
import { redisRbacRepository, type FlatRolesMap, type GroupDefinition } from './redis-rbac.repository.js'

/**
 * What a group hands out, per scope, and whether somebody already holds it — the "grant only what
 * you hold" rule (rbac-escalation-guard.ts).
 *
 * Resolved by scope, as rbac.rego resolves it: role names bound under `global` are read in
 * `roles.global`, role names bound under an app in THAT app's roles. A global permission applies in
 * every app, so what somebody holds in an app is their global permissions plus that app's; what they
 * hold globally is only the global ones — a grant everywhere needs a holding everywhere.
 */

export const GLOBAL = 'global'

/** scope → permissions (sorted, unique). */
export type PermissionsByScope = Record<string, string[]>

/** scope → that scope's role definitions (null: no such scope). */
export type RolesByScope = Record<string, FlatRolesMap | null | undefined>

/** The staff groups (policy/roles.ts) and super_admins: handed out and edited by a super admin only. */
export const STAFF_GROUPS: readonly string[] = STAFF_ROLES.map((r) => ROLES[r].group)

export function isStaffGroup(name: string): boolean {
  return STAFF_GROUPS.includes(name)
}

const sorted = (set: Iterable<string>): string[] => [...new Set(set)].sort()

/** What one definition grants in each scope it binds (scopes granting nothing left out). */
export function groupGrants(def: GroupDefinition | null | undefined, roles: RolesByScope): PermissionsByScope {
  const out: PermissionsByScope = {}
  for (const [scope, names] of Object.entries(def ?? {})) {
    const perms = (names ?? []).flatMap((r) => roles[scope]?.[r] ?? [])
    if (perms.length > 0) out[scope] = sorted(perms)
  }
  return out
}

/**
 * What these definitions hold together, in each of `scopes`: globally the global grants alone, in an
 * app the global grants and that app's.
 */
export function heldIn(defs: readonly (GroupDefinition | null | undefined)[], roles: RolesByScope, scopes: readonly string[]): PermissionsByScope {
  const each = defs.map((d) => groupGrants(d, roles))
  const global = each.flatMap((g) => g[GLOBAL] ?? [])
  const out: PermissionsByScope = {}
  for (const scope of new Set(scopes)) {
    out[scope] = sorted(scope === GLOBAL ? global : [...global, ...each.flatMap((g) => g[scope] ?? [])])
  }
  return out
}

/**
 * Whether held permissions cover a granted one: `*`, itself, a legacy alias of it (catalog.ts
 * `grants`) — or, when the granted name is itself a legacy alias, every permission it stands for.
 */
export function covers(held: readonly string[], permission: string): boolean {
  if (grants(held, permission)) return true
  const implied = ALIASES[permission]
  return !!implied && implied.every((p) => grants(held, p))
}

/** What `granted` names that `held` does not cover, per scope; empty when it is a subset. */
export function exceeding(granted: PermissionsByScope, held: PermissionsByScope): PermissionsByScope {
  const out: PermissionsByScope = {}
  for (const [scope, perms] of Object.entries(granted)) {
    const missing = perms.filter((p) => !covers(held[scope] ?? [], p))
    if (missing.length > 0) out[scope] = missing
  }
  return out
}

export function isEmpty(byScope: PermissionsByScope): boolean {
  return Object.values(byScope).every((p) => p.length === 0)
}

/** Every permission name in it, once. */
export function flatten(byScope: PermissionsByScope): string[] {
  return sorted(Object.values(byScope).flat())
}

/** Whether it hands out `*` anywhere. */
export function grantsWildcard(byScope: PermissionsByScope): boolean {
  return Object.values(byScope).some((p) => p.includes(EVERYTHING))
}

/** The current role definitions of these scopes, read once each. */
export async function loadRoles(scopes: Iterable<string>): Promise<RolesByScope> {
  const list = [...new Set(scopes)]
  const read = await Promise.all(list.map((s) => redisRbacRepository.getRoles(s)))
  return Object.fromEntries(list.map((s, i) => [s, read[i]]))
}

/** What these groups hold in each of `scopes`, from the current model. */
export async function heldByGroups(groups: readonly string[], scopes: readonly string[]): Promise<PermissionsByScope> {
  const defs = await redisRbacRepository.getGroups()
  const mine = groups.map((g) => defs[g])
  const roles = await loadRoles([GLOBAL, ...scopes])
  return heldIn(mine, roles, scopes)
}
