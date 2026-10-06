import { env } from '../config/index.js'
import { redisRbacRepository, type FlatRolesMap, type GroupDefinition } from './redis-rbac.repository.js'
import { KEYLESS_APPS, isGrantableScope } from './authorization-resolution.js'
import { isStaffGroup } from '../policy/roles.js'

/**
 * The scopes an API key of ONE organization may be given, and what they stand for. Org keys are made
 * by staff (orgs.keys:write); a key belongs to one organization and is valid on every site serving it
 * (org_sites), never on the platform's own apps (jinbe, kuma, global). A scope is, as granular as the
 * person making the key wants:
 *
 *   resource:verb        a permission a route of one of those sites asks for
 *   role:<site>:<role>   a site role of one of those sites: its permissions as the site defines them
 *   group:<group>        a platform group binding roles of those sites only: their permissions
 *
 * `role:` and `group:` are read first, so a permission of resource `role` or `group` reaches a key
 * through a role only. Staff groups (jinbe's) are never offered, nor a group binding another app.
 * API_KEY_ALLOWED_SCOPES, when set, caps the permissions a key ends up with (a ceiling, never a
 * widening).
 *
 * The policy reads only the expansion — data.api_clients[client].scopes, permissions (api-clients.ts)
 * — redone on every feed, so a role or group edited on a site follows at once, and a site that stops
 * serving the org takes its part of the key with it.
 */

export const ROLE_SCOPE = /^role:([a-z][a-z0-9-]{1,39}):([a-z][a-z0-9_-]{0,39})$/
export const GROUP_SCOPE = /^group:([A-Za-z0-9][A-Za-z0-9_.-]{0,63})$/

/** Whether a string can be a key scope at all: a role, a group, or a plain permission — never a wildcard. */
export const isKeyScope = (scope: string): boolean =>
  scope.startsWith('role:') ? ROLE_SCOPE.test(scope) : scope.startsWith('group:') ? GROUP_SCOPE.test(scope) : isGrantableScope(scope)

export interface ScopeCatalogEntry {
  scope: string
  kind: 'permission' | 'role' | 'group'
  /** The sites where it opens something. */
  sites: string[]
  /** What it stands for today. */
  permissions: string[]
}

/** What expanding scopes reads: every site's roles and route permissions, the groups, the entitlements. */
export interface KeyModel {
  orgSites: Record<string, string[]>
  roles: Record<string, FlatRolesMap>
  groups: Record<string, GroupDefinition>
  asked: Record<string, string[]>
}

const SYSTEM = new Set<string>(KEYLESS_APPS)
const sorted = (xs: Iterable<string>) => [...new Set(xs)].sort()

function withinCeiling(permission: string): boolean {
  const ceiling = env.API_KEY_ALLOWED_SCOPES
  return ceiling.length === 0 || ceiling.includes(permission)
}

/** The sites a key of `org` is valid on: those serving it, the platform's own apps left out. */
export const keySites = (model: Pick<KeyModel, 'orgSites'>, org: string): string[] => sorted((model.orgSites[org] ?? []).filter((s) => !SYSTEM.has(s)))

/** Reads the model once (one feed, or one catalogue). Throws when Redis cannot answer. */
export async function loadKeyModel(): Promise<KeyModel> {
  const [orgSites, groups] = await Promise.all([redisRbacRepository.getOrgSites(), redisRbacRepository.getGroups()])
  const sites = sorted(Object.values(orgSites).flat().filter((s) => !SYSTEM.has(s)))
  const roles: KeyModel['roles'] = {}
  const asked: KeyModel['asked'] = {}
  await Promise.all(sites.map(async (site) => {
    roles[site] = (await redisRbacRepository.getRoles(site)) ?? {}
    asked[site] = sorted(((await redisRbacRepository.getRouteMap(site))?.rules ?? []).map((r) => r.permission).filter((p): p is string => typeof p === 'string' && isGrantableScope(p)))
  }))
  return { orgSites, roles, groups, asked }
}

const permissionsOf = (perms: readonly string[]) => sorted(perms.filter((p) => isGrantableScope(p) && withinCeiling(p)))

/** A group's sites, when it may be a key scope for these sites (null otherwise). */
function groupSites(name: string, def: GroupDefinition | undefined, sites: readonly string[]): string[] | null {
  if (!def || isStaffGroup(name)) return null
  const apps = Object.keys(def)
  return apps.length > 0 && apps.every((a) => sites.includes(a)) ? sorted(apps) : null
}

/** What one scope of a key of `org` stands for today: [] when it opens nothing (any more). */
export function expandScope(model: KeyModel, org: string, scope: string): string[] {
  const sites = keySites(model, org)
  if (scope.startsWith('role:')) {
    const role = ROLE_SCOPE.exec(scope)
    return role && sites.includes(role[1]) ? permissionsOf(model.roles[role[1]]?.[role[2]] ?? []) : []
  }
  if (scope.startsWith('group:')) {
    const group = GROUP_SCOPE.exec(scope)
    const def = group ? model.groups[group[1]] : undefined
    const on = group ? groupSites(group[1], def, sites) : null
    return on ? permissionsOf(on.flatMap((site) => (def![site] ?? []).flatMap((r) => model.roles[site]?.[r] ?? []))) : []
  }
  return isGrantableScope(scope) && sites.some((s) => model.asked[s]?.includes(scope)) && withinCeiling(scope) ? [scope] : []
}

/** The permissions a key's scopes expand to: what the policy decides it on. */
export function expandScopes(model: KeyModel, org: string, scopes: readonly string[]): string[] {
  return sorted(scopes.flatMap((s) => expandScope(model, org, s)))
}

/**
 * The catalogue for a key of `organizationId`: every permission, role and group it may be given,
 * each with the sites it opens something on and what it stands for, sorted by scope. Only entries
 * that carry at least one permission. Throws when Redis cannot answer.
 */
export async function scopeCatalog(organizationId: string, model?: KeyModel): Promise<ScopeCatalogEntry[]> {
  const m = model ?? (await loadKeyModel())
  const sites = keySites(m, organizationId)
  const out: ScopeCatalogEntry[] = []
  const perms = new Map<string, string[]>()
  for (const site of sites) {
    for (const p of m.asked[site] ?? []) if (withinCeiling(p) && !/^(role|group):/.test(p)) perms.set(p, [...(perms.get(p) ?? []), site])
  }
  for (const [scope, on] of perms) out.push({ scope, kind: 'permission', sites: sorted(on), permissions: [scope] })
  for (const site of sites) {
    for (const [role, rolePerms] of Object.entries(m.roles[site] ?? {})) {
      const permissions = permissionsOf(rolePerms)
      if (permissions.length) out.push({ scope: `role:${site}:${role}`, kind: 'role', sites: [site], permissions })
    }
  }
  for (const [name, def] of Object.entries(m.groups)) {
    const on = groupSites(name, def, sites)
    if (!on || !GROUP_SCOPE.test(`group:${name}`)) continue
    const permissions = expandScope(m, organizationId, `group:${name}`)
    if (permissions.length) out.push({ scope: `group:${name}`, kind: 'group', sites: on, permissions })
  }
  return out.sort((a, b) => a.scope.localeCompare(b.scope))
}
