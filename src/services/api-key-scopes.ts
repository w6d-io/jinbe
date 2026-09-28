import { env } from '../config/index.js'
import { isSuperAdmin, rights } from '../authz/opa.js'
import { redisRbacRepository } from './redis-rbac.repository.js'
import { orgGrantsRepository } from './org-grants.repository.js'
import { covers, isGrantableScope } from './authorization-resolution.js'

/**
 * The scopes an API key of ONE organization may be given: a scope is a permission (`resource:verb`),
 * and the catalog is derived per org, never written down.
 *
 * A permission is offered when ALL hold:
 *   - a route of a site the organization runs requires it (data.org_service_map[org] → each site's
 *     route_map). A permission no route asks for would open nothing;
 *   - the person creating the key holds it there — the set the org layer decides with: site grants
 *     (their groups' roles in that site) ∪ org_grants[org] in that site, or a global/site `*` — matched
 *     exactly, as the gateway matches a site route. A key never carries more than its creator could do;
 *   - API_KEY_ALLOWED_SCOPES, when set, covers it (a ceiling, never a widening);
 *   - it is grantable: no `*`, no wildcard verb.
 *
 * Grouped by permission, listing the sites whose routes ask for it, so a console can show what each
 * scope opens.
 */

export interface ScopeCatalogEntry {
  scope: string
  sites: string[]
}

async function heldIn(email: string, site: string, grantedGroups: readonly string[]): Promise<string[]> {
  const held = new Set((await rights(email, site)).permissions)
  if (grantedGroups.length > 0) {
    // org_permissions(email, org, svc) in org.rego: the granted groups' roles IN THIS SITE only.
    const groups = await redisRbacRepository.getGroups()
    const roles = (await redisRbacRepository.getRoles(site)) ?? {}
    for (const group of grantedGroups) {
      for (const role of groups[group]?.[site] ?? []) for (const p of roles[role] ?? []) held.add(p)
    }
  }
  return [...held]
}

function withinCeiling(scope: string): boolean {
  const ceiling = env.API_KEY_ALLOWED_SCOPES
  return ceiling.length === 0 || ceiling.some((c) => covers(c, scope))
}

/**
 * The catalog for `email` creating a key in `organizationId`, sorted by scope. Throws
 * AuthzUnavailableError when OPA cannot be asked — "could not tell" is never an empty catalog.
 */
export async function scopeCatalog(organizationId: string, email: string): Promise<ScopeCatalogEntry[]> {
  const sites = (await redisRbacRepository.getOrgServiceMap())[organizationId] ?? []
  if (sites.length === 0) return []

  const everything = await isSuperAdmin(email)
  const granted = everything ? [] : await orgGrantsRepository.getForMember(organizationId, email.toLowerCase())

  const bySite = new Map<string, Set<string>>()
  for (const site of [...new Set(sites)].sort()) {
    const routeMap = await redisRbacRepository.getRouteMap(site)
    const asked = new Set(
      (routeMap?.rules ?? [])
        .map((r) => r.permission)
        .filter((p): p is string => typeof p === 'string' && isGrantableScope(p) && withinCeiling(p)),
    )
    if (asked.size === 0) continue
    const held = everything ? ['*'] : await heldIn(email, site, granted)
    const star = held.includes('*')
    for (const permission of asked) {
      // Exactly as the gateway grants a site route (rbac.rego user_has_permission): the permission
      // itself or `*` — no dotted ancestry there, so none here, or the catalog would offer a scope
      // the user could not use.
      if (!star && !held.includes(permission)) continue
      const entry = bySite.get(permission) ?? new Set<string>()
      entry.add(site)
      bySite.set(permission, entry)
    }
  }

  return [...bySite.entries()]
    .map(([scope, s]) => ({ scope, sites: [...s].sort() }))
    .sort((a, b) => a.scope.localeCompare(b.scope))
}
