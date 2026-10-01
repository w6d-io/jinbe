import { CATALOG, PERMISSIONS, type Permission, type PermissionSpec } from '../policy/catalog.js'

/**
 * The v2 permission catalogue (authz-v2-design §2.1): every v1 leaf, plus a SCOPE.
 *
 *   platform  decided on routes WITHOUT an org parameter, held through platform roles via groups
 *   org       decided ONLY on routes with an org parameter, held through org roles assigned to the
 *             person IN THAT ORG (or the explicit every-org map, roles.ts); meaningless elsewhere
 *
 * Routes keep declaring v1 names until the cut-over (the v1 gateway still matches them); the v2 name
 * of a route's permission is read off its shape (`v2Name`). The platform permissions about orgs are
 * renamed `orgs:*` so the two namespaces cannot be confused.
 *
 * No `*`, no alias, no ancestry: `grants(held, p)` is `held.includes(p)` (holding.ts).
 */

export type Scope = 'platform' | 'org'

export interface PermissionSpecV2 extends PermissionSpec {
  scope: Scope
  /** The v1 leaf this one comes from, or null for a permission new in v2. */
  from: Permission | null
}

/** The org-scoped leaves (§2.1 table). A route carrying one of these must name an org parameter. */
export const ORG_PERMISSIONS = [
  'org.members:read', 'org.members:write', 'org.keys:read', 'org.keys:write', 'org.keys:revoke', 'org.audit:read',
] as const

export type OrgPermission = (typeof ORG_PERMISSIONS)[number]

/** v1 name on a PLATFORM route → its v2 platform name, where it changes. */
export const PLATFORM_RENAMES: Readonly<Partial<Record<Permission, string>>> = {
  'org:read': 'orgs:read',
  'org:write': 'orgs:write',
  'org:delete': 'orgs:delete',
  'org.admins:write': 'orgs.owners:write',
  // PATCH /api/admin/users/:id/organization moves a person between orgs from the platform console.
  'org.members:write': 'orgs.members:write',
}

const relabel: Partial<Record<string, string>> = {
  'orgs:read': 'List organisations and their owners',
  'orgs.owners:write': "Name an organisation's owners (onboarding, break-glass)",
  'orgs.members:write': "Move a person into or out of an organisation from the platform console",
  'org.members:read': "See this organisation's members and their roles",
  'org.members:write': "Invite and remove this organisation's members, assign their roles",
}

function build(): Record<string, PermissionSpecV2> {
  const out: Record<string, PermissionSpecV2> = {}
  const orgSet = new Set<string>(ORG_PERMISSIONS)
  for (const v1 of PERMISSIONS) {
    const spec = CATALOG[v1]
    if (orgSet.has(v1)) out[v1] = { ...spec, scope: 'org', from: v1 }
    const renamed = PLATFORM_RENAMES[v1]
    if (renamed) out[renamed] = { ...spec, scope: 'platform', from: v1 }
    else if (!orgSet.has(v1)) out[v1] = { ...spec, scope: 'platform', from: v1 }
  }
  out['org.audit:read'] = {
    area: 'organizations', label: "Read this organisation's audit events", sensitivity: 'medium',
    stepUp: false, fourEyes: false, delegable: 'direct', scope: 'org', from: null,
  }
  for (const [name, label] of Object.entries(relabel)) if (out[name] && label) out[name] = { ...out[name], label }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)))
}

export const CATALOG_V2: Readonly<Record<string, PermissionSpecV2>> = build()

export const PERMISSIONS_V2 = Object.keys(CATALOG_V2)
export const PLATFORM_PERMISSIONS_V2 = PERMISSIONS_V2.filter((p) => CATALOG_V2[p].scope === 'platform')
export const ORG_PERMISSIONS_V2 = PERMISSIONS_V2.filter((p) => CATALOG_V2[p].scope === 'org')

export function isV2Permission(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(CATALOG_V2, name)
}

export function scopeOf(name: string): Scope | undefined {
  return isV2Permission(name) ? CATALOG_V2[name].scope : undefined
}

export class V2NameError extends Error {}

/**
 * The v2 name of a v1 permission declared on a route of this shape: unchanged on an org route (it
 * must be an org leaf), renamed per PLATFORM_RENAMES on a platform route (it must then be a platform
 * leaf). Throws on a mismatch, which is what keeps "org scope ⇔ org parameter" true.
 */
export function v2Name(v1: string, routeIsOrg: boolean): string {
  if (routeIsOrg) {
    if (scopeOf(v1) !== 'org') throw new V2NameError(`'${v1}' is not an org permission, but the route names an org parameter`)
    return v1
  }
  const name = PLATFORM_RENAMES[v1 as Permission] ?? v1
  if (scopeOf(name) !== 'platform') throw new V2NameError(`'${v1}' is an org permission, but the route names no org parameter`)
  return name
}

/** v2 name for a held/required v1 name outside a route (platform reading), or null when it has none. */
export function platformNameOf(v1: string): string | null {
  const name = PLATFORM_RENAMES[v1 as Permission] ?? v1
  return scopeOf(name) === 'platform' ? name : null
}
