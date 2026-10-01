import { redisRbacRepository, type FlatRolesMap, type GroupDefinition } from './redis-rbac.repository.js'

/**
 * What a group hands out, per app, and whether somebody already holds it — the holding rule
 * (rbac-escalation-guard.ts, authz-v2-design §1.1).
 *
 * Resolved by app, as rbac.rego resolves it: role names bound under an app are read in THAT app's
 * roles. There is no global scope and no wildcard: holding a permission in one app says nothing about
 * another, and a grant in an app needs the holding in that app.
 */

/** app → permissions (sorted, unique). */
export type PermissionsByScope = Record<string, string[]>

/** app → that app's role definitions (null: no such app). */
export type RolesByScope = Record<string, FlatRolesMap | null | undefined>

export { isStaffGroup } from '../policy/roles.js'

const sorted = (set: Iterable<string>): string[] => [...new Set(set)].sort()

/** What one definition grants in each app it binds (apps granting nothing left out). */
export function groupGrants(def: GroupDefinition | null | undefined, roles: RolesByScope): PermissionsByScope {
  const out: PermissionsByScope = {}
  for (const [scope, names] of Object.entries(def ?? {})) {
    const perms = (names ?? []).flatMap((r) => roles[scope]?.[r] ?? [])
    if (perms.length > 0) out[scope] = sorted(perms)
  }
  return out
}

/** What these definitions hold together, in each of `scopes`. */
export function heldIn(defs: readonly (GroupDefinition | null | undefined)[], roles: RolesByScope, scopes: readonly string[]): PermissionsByScope {
  const each = defs.map((d) => groupGrants(d, roles))
  const out: PermissionsByScope = {}
  for (const scope of new Set(scopes)) out[scope] = sorted(each.flatMap((g) => g[scope] ?? []))
  return out
}

/** What `granted` names that `held` does not hold, per app; empty when it is a subset. */
export function exceeding(granted: PermissionsByScope, held: PermissionsByScope): PermissionsByScope {
  const out: PermissionsByScope = {}
  for (const [scope, perms] of Object.entries(granted)) {
    const missing = perms.filter((p) => !(held[scope] ?? []).includes(p))
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

/** The current role definitions of these apps, read once each. */
export async function loadRoles(scopes: Iterable<string>): Promise<RolesByScope> {
  const list = [...new Set(scopes)]
  const read = await Promise.all(list.map((s) => redisRbacRepository.getRoles(s)))
  return Object.fromEntries(list.map((s, i) => [s, read[i]]))
}

/** The current every-org definitions of these apps (role → org permissions carried into every org). */
export async function loadEveryOrg(scopes: Iterable<string>): Promise<RolesByScope> {
  const list = [...new Set(scopes)]
  const read = await Promise.all(list.map((s) => redisRbacRepository.getEveryOrg(s)))
  return Object.fromEntries(list.map((s, i) => [s, read[i]]))
}

/** What these groups hold in each of `scopes`, from the current model. */
export async function heldByGroups(groups: readonly string[], scopes: readonly string[]): Promise<PermissionsByScope> {
  const defs = await redisRbacRepository.getGroups()
  return heldIn(groups.map((g) => defs[g]), await loadRoles(scopes), scopes)
}

/** What these groups carry into every org, in each of `scopes`. */
export async function everyOrgByGroups(groups: readonly string[], scopes: readonly string[]): Promise<PermissionsByScope> {
  const defs = await redisRbacRepository.getGroups()
  return heldIn(groups.map((g) => defs[g]), await loadEveryOrg(scopes), scopes)
}
