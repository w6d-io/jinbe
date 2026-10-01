import type { DataV2 } from './resolve.js'
import { everyOrgPermissions, orgPermissions, platformPermissions } from './resolve.js'
import { CATALOG_V2 } from './catalogue.js'
import { JINBE, staffGroupsV2 } from './roles.js'

/**
 * The holding rule (authz-v2-design §1.1, §2.5): the ONE grant service of v2. It replaces
 * `EVERYTHING`, `isSuperAdmin`, `requireGlobalSuperAdmin` and the aliases.
 *
 * To hand something out, the actor needs the grant permission AND must hold every permission the
 * grant confers, in the same scope. A super admin passes because they hold everything, never
 * because they are special. Taking power away needs no holding: a removal never escalates.
 *
 * Pure functions over data.v2, so the plan, the API and the contract tests agree with the policy.
 */

/** v2 grants: the permission itself. Nothing else is ever enough. */
export function grants(held: readonly string[], required: string): boolean {
  return held.includes(required)
}

/** What a grant confers, per app: platform permissions, and org permissions carried into every org. */
export interface Conferred {
  platform: Record<string, string[]>
  everyOrg: Record<string, string[]>
}

export type HoldingVerdict =
  | { ok: true }
  | { ok: false; reason: 'grant_permission_missing' | 'grant_exceeds_own' | 'not_org_member' | 'org_not_entitled' | 'unknown_role' | 'unknown_group' | 'defined_in_code'; permission?: string; missing?: Conferred }

const sorted = (xs: Iterable<string>) => [...new Set(xs)].sort()

/** What a group definition confers, resolved against the v2 roles. */
export function conferredByDefinition(d: DataV2, def: Record<string, readonly string[]>): Conferred {
  const platform: Record<string, string[]> = {}
  const everyOrg: Record<string, string[]> = {}
  for (const [app, roles] of Object.entries(def)) {
    const p = sorted(roles.flatMap((r) => d.roles[app]?.[r] ?? []))
    const e = sorted(roles.flatMap((r) => d.every_org[app]?.[r] ?? []))
    if (p.length) platform[app] = p
    if (e.length) everyOrg[app] = e
  }
  return { platform, everyOrg }
}

/** What `email` holds in the shape of `conferred`, app by app. */
function actorHolds(d: DataV2, email: string, conferred: Conferred): Conferred {
  const apps = new Set([...Object.keys(conferred.platform), ...Object.keys(conferred.everyOrg)])
  const platform: Record<string, string[]> = {}
  const everyOrg: Record<string, string[]> = {}
  for (const app of apps) {
    platform[app] = platformPermissions(d, email, app)
    everyOrg[app] = everyOrgPermissions(d, email, app)
  }
  return { platform, everyOrg }
}

/** What `conferred` grants beyond `held`, empty when nothing. */
export function exceeding(conferred: Conferred, held: Conferred): Conferred {
  const diff = (a: Record<string, string[]>, b: Record<string, string[]>) =>
    Object.fromEntries(
      Object.entries(a)
        .map(([app, perms]) => [app, perms.filter((p) => !(b[app] ?? []).includes(p))] as const)
        .filter(([, perms]) => perms.length > 0),
    )
  return { platform: diff(conferred.platform, held.platform), everyOrg: diff(conferred.everyOrg, held.everyOrg) }
}

export const isNothing = (c: Conferred) => Object.keys(c.platform).length === 0 && Object.keys(c.everyOrg).length === 0

/** Code-owned groups (staff groups, super_admins): never editable through the API (409). */
export function isCodeOwnedGroup(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(staffGroupsV2(), name)
}

function holding(d: DataV2, actor: string, grantPermission: string, conferred: Conferred): HoldingVerdict {
  if (!grants(platformPermissions(d, actor, JINBE), grantPermission)) {
    return { ok: false, reason: 'grant_permission_missing', permission: grantPermission }
  }
  const missing = exceeding(conferred, actorHolds(d, actor, conferred))
  return isNothing(missing) ? { ok: true } : { ok: false, reason: 'grant_exceeds_own', missing }
}

/** `can_add_to_group`: groups.members:write, and holding everything the group confers. */
export function mayAddToGroup(d: DataV2, actor: string, group: string): HoldingVerdict {
  if (!d.groups[group]) return { ok: false, reason: 'unknown_group' }
  return holding(d, actor, 'groups.members:write', conferredByDefinition(d, d.groups[group] ?? {}))
}

/**
 * A group definition after a change (`groups:write`): code-owned groups are refused outright, the
 * rest need everything the definition confers AFTER the change. A deletion confers nothing.
 */
export function mayDefineGroup(d: DataV2, actor: string, group: string, after: Record<string, readonly string[]> | null): HoldingVerdict {
  if (isCodeOwnedGroup(group)) return { ok: false, reason: 'defined_in_code' }
  return holding(d, actor, 'groups:write', after ? conferredByDefinition(d, after) : { platform: {}, everyOrg: {} })
}

/**
 * `can_assign`: an org role (`svc:role`) to a member of `org`. The actor holds `org.members:write`
 * in that org and every permission of the role in that org, for its service; the org is entitled to
 * the service.
 */
export function mayAssignOrgRole(d: DataV2, actor: string, org: string, role: string, granteeIsMember: boolean): HoldingVerdict {
  if (!orgPermissions(d, actor, org, JINBE).includes('org.members:write')) {
    return { ok: false, reason: 'grant_permission_missing', permission: 'org.members:write' }
  }
  if (!granteeIsMember) return { ok: false, reason: 'not_org_member' }
  const [svc, name, ...rest] = role.split(':')
  const perms = rest.length === 0 && name ? d.org_roles[svc]?.[name] : undefined
  if (!perms) return { ok: false, reason: 'unknown_role' }
  if (!(d.org_sites[org] ?? []).includes(svc)) return { ok: false, reason: 'org_not_entitled' }
  const held = orgPermissions(d, actor, org, svc)
  const missing = perms.filter((p) => !held.includes(p))
  return missing.length === 0 ? { ok: true } : { ok: false, reason: 'grant_exceeds_own', missing: { platform: {}, everyOrg: { [svc]: sorted(missing) } } }
}

/** The org roles `actor` may hand out in `org` (what `GET …/roles` marks assignable). */
export function assignableOrgRoles(d: DataV2, actor: string, org: string): string[] {
  const out: string[] = []
  for (const [svc, roles] of Object.entries(d.org_roles)) {
    for (const name of Object.keys(roles)) {
      const q = `${svc}:${name}`
      if (mayAssignOrgRole(d, actor, org, q, true).ok) out.push(q)
    }
  }
  return out.sort()
}

/**
 * Token scopes (a personal or org key): each must be held, in the scope the key acts in, and none
 * may be `delegable: never`.
 */
export function mayScopeKey(held: readonly string[], scopes: readonly string[]): { ok: boolean; notHeld: string[]; neverDelegable: string[] } {
  const notHeld = scopes.filter((s) => !held.includes(s))
  const neverDelegable = scopes.filter((s) => CATALOG_V2[s]?.delegable === 'never')
  return { ok: notHeld.length === 0 && neverDelegable.length === 0, notHeld, neverDelegable }
}
