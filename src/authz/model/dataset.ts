import type { PolicyData } from './resolve.js'
import type { FlatRolesMap, GroupDefinition, RouteRule } from '../../services/redis-rbac.repository.js'
import type { OrgAssignments } from '../../services/org-roles.repository.js'
import { directBinding, type DirectBinding, type DirectGrant } from '../../services/direct-grants.repository.js'
import { JINBE } from '../../policy/roles.js'

/**
 * The policy data assembled from what the store holds (definitions) and who is in what (the
 * identities, the org role assignments) — the same projection the OPAL feeds make, pure, so the plan
 * and the tests build exactly what OPA will read.
 *
 * A group membership naming a group nothing defines, and an org role held where the person is not a
 * member, are left out of the policy (never off the identity: owner decision D4); the plan lists both.
 */

export interface IdentityFacts {
  id: string | null
  groups: readonly string[]
  /** Every org the person belongs to (primary included). */
  organizations: readonly string[]
}

export interface StoredModel {
  roles: Record<string, FlatRolesMap>
  groups: Record<string, GroupDefinition>
  orgRoles: Record<string, FlatRolesMap>
  everyOrg: Record<string, FlatRolesMap>
  routeMap: Record<string, { rules: RouteRule[] }>
  /** org → sites it is entitled to (jinbe is added for every org). */
  orgSites: Record<string, string[]>
}

export function buildPolicyData(
  model: StoredModel,
  identities: ReadonlyMap<string, IdentityFacts>,
  assignments: OrgAssignments,
  knownOrgs: readonly string[],
  grants: Readonly<Record<string, readonly DirectGrant[]>> = {},
  now = Date.now(),
): PolicyData {
  const group_membership: Record<string, string[]> = {}
  const direct: Record<string, DirectBinding> = {}
  const user_organizations: Record<string, string[]> = {}
  const org_assignments: Record<string, Record<string, string[]>> = {}
  const orgs = new Set([...knownOrgs, ...Object.keys(model.orgSites)])

  const put = <T>(map: Record<string, T>, email: string, value: T) => {
    map[email] = value
    const lower = email.toLowerCase()
    if (lower !== email && !(lower in map)) map[lower] = value
  }

  for (const [email, facts] of [...identities.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const groups = [...new Set(facts.groups.filter((g) => g in model.groups))].sort()
    if (groups.length) put(group_membership, email, groups)
    const memberOf = [...new Set(facts.organizations)].sort()
    if (memberOf.length) put(user_organizations, email, memberOf)
    for (const o of memberOf) orgs.add(o)
    const mine: Record<string, string[]> = {}
    for (const org of memberOf) {
      const roles = facts.id ? assignments[org]?.[facts.id] : undefined
      if (roles?.length) mine[org] = [...roles].sort()
    }
    if (Object.keys(mine).length) put(org_assignments, email, mine)
    const held = facts.id ? directBinding(grants[facts.id] ?? [], memberOf, now) : null
    if (held) put(direct, email, held)
  }

  const org_sites: Record<string, string[]> = {}
  for (const o of [...orgs].sort()) org_sites[o] = [...new Set([JINBE, ...(model.orgSites[o] ?? [])])]

  return {
    roles: model.roles,
    groups: model.groups,
    group_membership,
    user_organizations,
    org_roles: model.orgRoles,
    org_assignments,
    direct,
    every_org: model.everyOrg,
    org_sites,
    route_map: model.routeMap,
  }
}
