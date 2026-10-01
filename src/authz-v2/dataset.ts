import type { DataV2 } from './resolve.js'
import type { readV2Keys } from './store.js'
import { CATALOG_V2 } from './catalogue.js'
import { JINBE } from './roles.js'

/**
 * data.v2 assembled from the rbac2 keys (what code and site intents define) and the identities (who
 * is in what). Pure, so the OPAL feed, the plan and the tests build the same document.
 *
 * Kept from the people: group memberships, org memberships, `organization_roles`. Dropped from the
 * POLICY (never from the identity, owner decision D4): a membership of a group v2 does not define,
 * and an org role that is not a qualified `svc:role`. The plan lists both as orphans.
 */

export interface IdentityFacts {
  groups: readonly string[]
  /** Every org the person belongs to (primary included). */
  organizations: readonly string[]
  /** metadata_admin.organization_roles, as stored. */
  organizationRoles: Readonly<Record<string, readonly string[]>>
}

export type V2Keys = Awaited<ReturnType<typeof readV2Keys>>

const QUALIFIED = /^[a-z0-9][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*$/

export function isQualifiedOrgRole(role: string): boolean {
  return QUALIFIED.test(role)
}

export function buildDataV2(keys: V2Keys, identities: ReadonlyMap<string, IdentityFacts>, knownOrgs: readonly string[]): DataV2 {
  const group_membership: Record<string, string[]> = {}
  const user_organizations: Record<string, string[]> = {}
  const org_assignments: Record<string, Record<string, string[]>> = {}
  const orgs = new Set(knownOrgs)

  const put = <T>(map: Record<string, T>, email: string, value: T) => {
    map[email] = value
    const lower = email.toLowerCase()
    if (lower !== email && !(lower in map)) map[lower] = value
  }

  for (const [email, facts] of [...identities.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const groups = [...new Set(facts.groups.filter((g) => g in keys.groups))].sort()
    if (groups.length) put(group_membership, email, groups)
    const memberOf = [...new Set(facts.organizations)].sort()
    if (memberOf.length) put(user_organizations, email, memberOf)
    for (const o of memberOf) orgs.add(o)
    const assigned: Record<string, string[]> = {}
    for (const [org, roles] of Object.entries(facts.organizationRoles)) {
      const q = [...new Set(roles.filter(isQualifiedOrgRole))].sort()
      if (q.length && memberOf.includes(org)) assigned[org] = q
    }
    if (Object.keys(assigned).length) put(org_assignments, email, assigned)
  }

  const org_sites: Record<string, string[]> = {}
  for (const o of [...orgs].sort()) org_sites[o] = [JINBE]

  const catalogue: DataV2['catalogue'] = {}
  for (const [name, spec] of Object.entries(CATALOG_V2)) {
    catalogue[name] = { scope: spec.scope, step_up: spec.stepUp, delegable: spec.delegable, four_eyes: spec.fourEyes }
  }

  return {
    version: 1,
    roles: keys.roles,
    groups: keys.groups,
    group_membership,
    user_organizations,
    org_roles: keys.orgRoles,
    org_assignments,
    every_org: keys.everyOrg,
    org_sites,
    route_map: keys.routeMap,
    catalogue,
  }
}
