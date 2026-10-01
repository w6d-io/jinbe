import { env } from '../config/index.js'
import { orgPermissionsByOrg, rights } from '../authz/opa.js'
import { redisRbacRepository } from './redis-rbac.repository.js'
import { isGrantableScope } from './authorization-resolution.js'

/**
 * The scopes an API key of ONE organization may be given: a scope is a permission (`resource:verb`),
 * and the catalog is derived per org, never written down.
 *
 * A permission is offered when ALL hold:
 *   - a route of a site the organization is entitled to requires it (data.org_sites[org] → each
 *     site's route_map). A permission no route asks for would open nothing;
 *   - the person creating the key holds it there — their platform roles in that site ∪ the org roles
 *     assigned to them in that org for that site (OPA) — matched exactly, as the gateway matches a
 *     site route. A key never carries more than its creator could do;
 *   - API_KEY_ALLOWED_SCOPES, when set, lists it (a ceiling, never a widening);
 *   - it is grantable: a plain `resource:verb`.
 *
 * Grouped by permission, listing the sites whose routes ask for it, so a console can show what each
 * scope opens.
 */

export interface ScopeCatalogEntry {
  scope: string
  sites: string[]
}

/** What `email` holds in one site for one org: platform roles there ∪ org roles in that org (OPA). */
export async function heldIn(email: string, site: string, organizationId: string): Promise<string[]> {
  const [platform, byOrg] = await Promise.all([rights(email, site), orgPermissionsByOrg(email, site)])
  return [...new Set([...platform.permissions, ...(byOrg[organizationId] ?? [])])]
}

function withinCeiling(scope: string): boolean {
  const ceiling = env.API_KEY_ALLOWED_SCOPES
  return ceiling.length === 0 || ceiling.includes(scope)
}

/**
 * The catalog for `email` creating a key in `organizationId`, sorted by scope. Throws
 * AuthzUnavailableError when OPA cannot be asked — "could not tell" is never an empty catalog.
 */
export async function scopeCatalog(organizationId: string, email: string): Promise<ScopeCatalogEntry[]> {
  const sites = (await redisRbacRepository.getOrgSites())[organizationId] ?? []
  if (sites.length === 0) return []

  const bySite = new Map<string, Set<string>>()
  for (const site of [...new Set(sites)].sort()) {
    const routeMap = await redisRbacRepository.getRouteMap(site)
    const asked = new Set(
      (routeMap?.rules ?? [])
        .map((r) => r.permission)
        .filter((p): p is string => typeof p === 'string' && isGrantableScope(p) && withinCeiling(p)),
    )
    if (asked.size === 0) continue
    const held = await heldIn(email, site, organizationId)
    for (const permission of asked) {
      // Exactly as the gateway grants a site route: the permission itself, nothing else.
      if (!held.includes(permission)) continue
      const entry = bySite.get(permission) ?? new Set<string>()
      entry.add(site)
      bySite.set(permission, entry)
    }
  }

  return [...bySite.entries()]
    .map(([scope, s]) => ({ scope, sites: [...s].sort() }))
    .sort((a, b) => a.scope.localeCompare(b.scope))
}
