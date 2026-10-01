import type { RouteRule } from '../../services/redis-rbac.repository.js'

/**
 * The policy data as OPAL publishes it for `package rbac` (data names agreed with opal-policies:
 * route_map, roles, bindings.groups, bindings.group_membership, bindings.user_organizations,
 * bindings.org_assignments, org_roles, every_org, org_sites), flattened, and the pure resolver over
 * it. The resolver mirrors the rego clause for clause (authz-v2-design §2.3, §2.5), so the plan, the
 * holding rule and the contract tests compute what the policy will.
 *
 * Nothing here has a wildcard, an alias or an ancestor: a permission is held or it is not.
 */

export interface PolicyData {
  /** Platform roles: app → role → permissions. */
  roles: Record<string, Record<string, string[]>>
  /** Group → app → roles. */
  groups: Record<string, Record<string, string[]>>
  /** Address → groups (only groups that exist in `groups`). */
  group_membership: Record<string, string[]>
  /** Address → orgs the person belongs to. */
  user_organizations: Record<string, string[]>
  /** Org roles: svc → role → permissions. */
  org_roles: Record<string, Record<string, string[]>>
  /** Address → org → `svc:role`. */
  org_assignments: Record<string, Record<string, string[]>>
  /** Platform role → the org permissions it holds in EVERY org: app → role → permissions. */
  every_org: Record<string, Record<string, string[]>>
  /** Org → the apps it is entitled to (`jinbe` always). */
  org_sites: Record<string, string[]>
  route_map: Record<string, { rules: RouteRule[] }>
}

const uniq = (xs: Iterable<string>) => [...new Set(xs)].sort()

/** Platform roles of `email` in `app` (via groups). */
export function platformRoles(d: PolicyData, email: string, app: string): string[] {
  const out: string[] = []
  for (const g of d.group_membership[email] ?? []) for (const r of d.groups[g]?.[app] ?? []) out.push(r)
  return uniq(out)
}

/** `user_permissions`: what `email` holds on platform (no org parameter) routes of `app`. */
export function platformPermissions(d: PolicyData, email: string, app: string): string[] {
  const out: string[] = []
  for (const r of platformRoles(d, email, app)) for (const p of d.roles[app]?.[r] ?? []) out.push(p)
  return uniq(out)
}

/** The every-org part of `org_permissions`: what a platform role carries into any org. */
export function everyOrgPermissions(d: PolicyData, email: string, app: string): string[] {
  const out: string[] = []
  for (const r of platformRoles(d, email, app)) for (const p of d.every_org[app]?.[r] ?? []) out.push(p)
  return uniq(out)
}

/** The assigned part of `org_permissions`: roles assigned in that org, member of it, org entitled. */
export function assignedOrgPermissions(d: PolicyData, email: string, org: string, app: string): string[] {
  if (!(d.user_organizations[email] ?? []).includes(org)) return []
  if (!(d.org_sites[org] ?? []).includes(app)) return []
  const out: string[] = []
  for (const q of d.org_assignments[email]?.[org] ?? []) {
    const [svc, role, ...rest] = q.split(':')
    if (rest.length > 0 || svc !== app || !role) continue
    for (const p of d.org_roles[svc]?.[role] ?? []) out.push(p)
  }
  return uniq(out)
}

/** `org_permissions(email, org, app)`. */
export function orgPermissions(d: PolicyData, email: string, org: string, app: string): string[] {
  return uniq([...assignedOrgPermissions(d, email, org, app), ...everyOrgPermissions(d, email, app)])
}

/** The orgs where `email` holds `permission` (every-org reaches every known org). */
export function orgsHolding(d: PolicyData, email: string, permission: string, app: string): string[] {
  const orgs = new Set([...Object.keys(d.org_sites), ...(d.user_organizations[email] ?? [])])
  return [...orgs].filter((o) => orgPermissions(d, email, o, app).includes(permission)).sort()
}
