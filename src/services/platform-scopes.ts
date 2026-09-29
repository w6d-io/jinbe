import { JINBE_APP, holds, isSuperAdmin, manageableOrgs, memberOrgs, rights } from '../authz/opa.js'
import { declaredRoutes } from '../policy/declared-routes.js'
import { ineligibleWhy } from '../middleware/delegation-gate.js'
import { grants, specOf } from '../policy/catalog.js'
import { heldIn } from './api-key-scopes.js'
import { orgGrantsRepository } from './org-grants.repository.js'
import { isGrantableScope } from './authorization-resolution.js'
import { ORG_ADMIN_PERMISSIONS } from './org-admin.js'

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
 *       · a platform route (policy/declared-routes.ts): what they hold in jinbe, global roles
 *         included, `*` and the catalogue's legacy aliases counting (`holds`);
 *       · a route of one org (declared org-scoped): held platform-wide as above, or in AT LEAST ONE
 *         org — super_admin, an org's roster admin for the org-management set, or a member holding it
 *         (legacy names counting) from their jinbe grants ∪ that org's org_grants. Which org a call
 *         may touch is still decided per request, by the normal rules;
 *   - it is grantable (no `*`, no wildcard verb): holding `*` yields the concrete permissions the
 *     routes declare, never `*` itself.
 *
 * API_KEY_ALLOWED_SCOPES is NOT applied: that ceiling bounds org machine keys (api-key-scopes.ts).
 * A personal key inherits its holder, bounded only by the ineligible list and the no-wildcard rule.
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
    // An org-scoped route is reachable platform-wide (a staff role) or through the org layer.
    mark(r.permission, 'platform')
    if (r.org) mark(r.permission, 'org')
  }
  return out
}

/** What `email` holds through the org layer, in any org they belong to. */
async function orgLayerHolds(email: string): Promise<(p: string) => boolean> {
  const orgs = await memberOrgs(email)
  if (orgs.length === 0) return () => false
  const administered = new Set(await manageableOrgs(email))
  const management = new Set<string>(ORG_ADMIN_PERMISSIONS)
  const held = new Set<string>()
  for (const org of orgs) {
    const granted = await orgGrantsRepository.getForMember(org, email.toLowerCase())
    for (const p of await heldIn(email, JINBE_APP, granted)) held.add(p)
  }
  const rosterAdmin = orgs.some((o) => administered.has(o))
  const names = [...held, ...(rosterAdmin ? management : [])]
  return (p) => grants(names, p)
}

/**
 * The jinbe permissions `email` holds that a personal key may carry, sorted. Throws
 * AuthzUnavailableError when OPA cannot be asked — "could not tell" is never an empty list.
 */
export async function platformScopes(email: string): Promise<string[]> {
  const reach = delegableJinbePermissions()
  if (reach.size === 0) return []

  const everything = await isSuperAdmin(email)
  const platformHeld = everything ? ['*'] : (await rights(email)).permissions
  const orgHolds = everything
    ? () => true
    : [...reach.values()].some((r) => r.org) ? await orgLayerHolds(email) : () => false

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
