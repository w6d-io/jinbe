import { holds, orgPermissionsByOrg, rights } from '../authz/opa.js'
import { declaredRoutes } from '../policy/declared-routes.js'
import { ineligibleWhy } from '../middleware/delegation-gate.js'
import { specOf } from '../policy/catalog.js'
import { isGrantableScope } from './authorization-resolution.js'

/**
 * What a PERSONAL key may carry: the permissions of jinbe's own API its holder holds — what the MCP
 * server's tools call (sites, users, groups, audit, an org's members). A personal key is not bound to
 * an organization and inherits its holder: by default everything they hold, re-read on every call;
 * optionally a subset of this list. Staff rights come from groups; orgs secure SITES (org machine
 * keys, api-key-scopes.ts) and are not what a personal key is about.
 *
 * A permission is listed when ALL hold:
 *   - a jinbe route requires it that a delegated caller may reach — a catalogue permission marked
 *     `delegable: 'direct'` (policy/catalog.ts), on a route outside the delegation gate's backstop
 *     list (middleware/delegation-gate.ts: keys, SCIM, infrastructure, policy data);
 *   - the holder passes that route's gate as a session would:
 *       · a platform route (policy/declared-routes.ts): their platform permissions in jinbe;
 *       · a route of one org (declared org-scoped): held in AT LEAST ONE org (an org role there, or
 *         the every-org map). Which org a call may touch is still decided per request;
 *   - it is grantable: a plain `resource:verb`.
 *
 * API_KEY_ALLOWED_SCOPES is NOT applied: that ceiling bounds org machine keys (api-key-scopes.ts).
 * A personal key inherits its holder, bounded only by the ineligible list.
 */

export interface PersonalScopeEntry {
  scope: string
  /** The resource root (`admin.organisation:read` → `admin`), for a grouped checklist. */
  group: string
}

type Reach = { platform: boolean; org: boolean }

function delegable(method: string, path: string, permission: string | undefined): permission is string {
  return typeof permission === 'string'
    && isGrantableScope(permission)
    && specOf(permission)?.delegable === 'direct'
    && ineligibleWhy(method, path) === null
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
    if (r.class !== 'authorized' || !delegable(r.method, r.path, r.permission)) continue
    mark(r.permission, r.org ? 'org' : 'platform')
  }
  return out
}

/**
 * The jinbe permissions `email` holds that a personal key may carry, sorted. Throws
 * AuthzUnavailableError when OPA cannot be asked — "could not tell" is never an empty list.
 */
export async function platformScopes(email: string): Promise<string[]> {
  const reach = delegableJinbePermissions()
  if (reach.size === 0) return []

  const platformHeld = (await rights(email)).permissions
  const orgHeld = [...reach.values()].some((r) => r.org)
    ? new Set(Object.values(await orgPermissionsByOrg(email)).flat())
    : new Set<string>()
  const orgHolds = (p: string) => orgHeld.has(p)

  return [...reach.entries()]
    .filter(([p, r]) => (r.platform && holds(platformHeld, p)) || (r.org && orgHolds(p)))
    .map(([p]) => p)
    .sort()
}

export const scopeGroup = (scope: string): string => scope.split(/[.:]/)[0]

/** The personal-key catalog, grouped by resource root then sorted by scope. */
export async function personalScopeCatalog(email: string): Promise<PersonalScopeEntry[]> {
  return (await platformScopes(email))
    .map((scope) => ({ scope, group: scopeGroup(scope) }))
    // Stable over the code-point order platformScopes gives, so each group keeps it.
    .sort((a, b) => (a.group < b.group ? -1 : a.group > b.group ? 1 : 0))
}
