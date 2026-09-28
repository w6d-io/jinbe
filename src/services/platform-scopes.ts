import { JINBE_APP, holds, isSuperAdmin, manageableOrgs, memberOrgs, rights } from '../authz/opa.js'
import { declaredRoutes } from '../policy/declared-routes.js'
import { JINBE_BUILT_IN_ROUTES } from '../bootstrap/build-route-map.js'
import { INELIGIBLE_PERMISSIONS, ineligibleWhy } from '../middleware/delegation-gate.js'
import { heldIn, scopeCatalog, withinCeiling, type ScopeCatalogEntry } from './api-key-scopes.js'
import { orgGrantsRepository } from './org-grants.repository.js'
import { isGrantableScope, permits } from './authorization-resolution.js'
import { USER_PERMISSIONS } from './user-permissions.js'
import { ORG_ADMIN_PERMISSIONS } from './org-admin.js'

/**
 * The scopes a PERSONAL key may be given: the org's site scopes (api-key-scopes.ts) ∪ the permissions
 * of jinbe's OWN API — what the MCP server's tools call (sites, users, groups, audit, the org's
 * members). An org machine key never gets the second half: no person stands behind it.
 *
 * A jinbe permission is offered when ALL hold:
 *   - a jinbe route requires it that a delegated caller may reach — never one only the always-refused
 *     routes ask for (middleware/delegation-gate.ts: keys, sign-in settings, the org-admin roster,
 *     SCIM, infrastructure, policy data, approvals) nor one no delegated caller may exercise;
 *   - the caller passes that route's gate as a session would:
 *       · a platform route (read off the guards, policy/declared-routes.ts): what they hold in jinbe,
 *         global roles included, `*` and ancestors covering (`holds`), plus the coarse permission a
 *         user-management one refines (user-permissions.ts) and `admin:read` for the audit trail
 *         (audit/query/scope.ts);
 *       · a route of THIS org (the jinbe route_map's org_param rows, decided by OPA's org layer):
 *         super_admin, the org's roster admin for the org-management set, or a member holding it —
 *         exactly or through `*` — from their jinbe grants ∪ org_grants of this org;
 *   - API_KEY_ALLOWED_SCOPES covers it, and it is grantable (no `*`, no wildcard verb): holding `*`
 *     yields the concrete permissions the routes declare, never `*` itself.
 */

/** The pseudo-site jinbe's own permissions are grouped under. */
export const PLATFORM_SITE = 'platform'

export type PersonalScopeEntry = ScopeCatalogEntry & { kind: 'site' | 'platform' }

type Reach = { platform: boolean; org: boolean }

function delegable(method: string, path: string, permission: string | undefined): permission is string {
  return typeof permission === 'string'
    && isGrantableScope(permission)
    && !INELIGIBLE_PERMISSIONS.has(permission)
    && ineligibleWhy(method, path) === null
    && withinCeiling(permission)
}

/** Every permission a delegated caller could use on jinbe, and through which layer. */
export function delegableJinbePermissions(): Map<string, Reach> {
  const out = new Map<string, Reach>()
  const mark = (permission: string, layer: keyof Reach) => {
    const reach = out.get(permission) ?? { platform: false, org: false }
    reach[layer] = true
    out.set(permission, reach)
  }

  for (const r of declaredRoutes()) {
    if (r.class === 'authorized' && delegable(r.method, r.path, r.permission)) mark(r.permission, 'platform')
  }

  // One org's routes: their guards are not marked, the route_map is what OPA decides them with. A
  // route matched by several rules needs any one; when one of them is the org-management permission
  // that is the one offered, not the legacy `admin:create` beside it.
  const byRoute = new Map<string, string[]>()
  for (const r of JINBE_BUILT_IN_ROUTES) {
    if (!r.org_param || !delegable(r.method, r.path, r.permission)) continue
    const key = `${r.method} ${r.path}`
    byRoute.set(key, [...(byRoute.get(key) ?? []), r.permission])
  }
  const management = new Set<string>(ORG_ADMIN_PERMISSIONS)
  for (const permissions of byRoute.values()) {
    const preferred = permissions.filter((p) => management.has(p))
    for (const p of preferred.length > 0 ? preferred : permissions) mark(p, 'org')
  }
  return out
}

function passesPlatformGate(held: readonly string[], required: string): boolean {
  if (holds(held, required)) return true
  const coarse = (USER_PERMISSIONS as Record<string, string>)[required]
  if (coarse && permits(held, coarse)) return true
  return required.startsWith('audit:') && holds(held, 'admin:read')
}

/**
 * The jinbe permissions `email` may put on a personal key bound to `organizationId`, sorted. Throws
 * AuthzUnavailableError when OPA cannot be asked.
 */
export async function platformScopes(organizationId: string, email: string): Promise<string[]> {
  const reach = delegableJinbePermissions()
  if (reach.size === 0) return []

  const everything = await isSuperAdmin(email)
  const platformHeld = everything ? ['*'] : (await rights(email)).permissions

  let orgHolds: (p: string) => boolean = () => everything
  if (!everything && [...reach.values()].some((r) => r.org)) {
    const member = (await memberOrgs(email)).includes(organizationId)
    const rosterAdmin = member && (await manageableOrgs(email)).includes(organizationId)
    const granted = member ? await orgGrantsRepository.getForMember(organizationId, email.toLowerCase()) : []
    const orgHeld = member ? await heldIn(email, JINBE_APP, granted) : []
    const management = new Set<string>(ORG_ADMIN_PERMISSIONS)
    orgHolds = (p) => orgHeld.includes('*') || orgHeld.includes(p) || (rosterAdmin && management.has(p))
  }

  return [...reach.entries()]
    .filter(([p, r]) => (r.platform && passesPlatformGate(platformHeld, p)) || (r.org && orgHolds(p)))
    .map(([p]) => p)
    .sort()
}

/** The personal-key catalog: site scopes ∪ jinbe's, one entry per scope. */
export async function personalScopeCatalog(organizationId: string, email: string): Promise<PersonalScopeEntry[]> {
  const [sites, platform] = await Promise.all([scopeCatalog(organizationId, email), platformScopes(organizationId, email)])
  const entries = new Map<string, PersonalScopeEntry>(sites.map((e) => [e.scope, { ...e, kind: 'site' }]))
  for (const scope of platform) {
    const site = entries.get(scope)
    entries.set(scope, site ? { ...site, sites: [...site.sites, PLATFORM_SITE].sort() } : { scope, sites: [PLATFORM_SITE], kind: 'platform' })
  }
  return [...entries.values()].sort((a, b) => a.scope.localeCompare(b.scope))
}
