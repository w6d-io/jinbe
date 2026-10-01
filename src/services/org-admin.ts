import type { FastifyRequest } from 'fastify'
import { manageableOrgs } from '../authz/opa.js'

/**
 * What administering one organisation gives, and nothing else: managing its people and its API keys
 * (the same set as `org_management_permission` in opal-policies rbac.rego, minus users:assign_group).
 *
 * Deliberately not `*`, not a service permission and not `users:assign_group`. Handing out a group
 * is a grant of rights: an org admin does that through the org-grant routes, where OPA's `can_grant`
 * bounds it to their own org and to what they hold — the site-wide group routes still refuse.
 */
export const ORG_ADMIN_PERMISSIONS = ['org:manage_users', 'org:manage_api_keys', 'users:read', 'users:create'] as const

/** The role the org-admin rights are reported under. */
export const ORG_ADMIN_ROLE = 'org_admin'

/**
 * Whether the caller administers THIS organisation, or null when that could not be established.
 *
 * Asked of OPA (`rbac.delegation.manageable_orgs`): on that org's roster AND a member of it — the
 * same conjunction the gateway applies, over the same data, so a stale roster entry for somebody who
 * left grants nothing here either.
 *
 * "Is not" and "cannot tell" stay apart: the gate turns the second into a 503 when nothing else
 * admits the caller, never into a quiet refusal.
 */
export async function administersOrganisation(
  request: FastifyRequest,
  organisationId: string,
): Promise<boolean | null> {
  const email = request.userContext?.email
  if (!email || email === 'unknown' || !organisationId) return false

  try {
    return (await manageableOrgs(email)).includes(organisationId)
  } catch (err) {
    request.log.warn({ organisationId, err: (err as Error).message }, '[org-admin] OPA could not say who administers the organisation')
    return null
  }
}

/** Why somebody on an org's roster does not administer it (the gateway would refuse them). */
export type NotAdminWhy = 'not_a_member_per_policy' | 'email_case_mismatch' | 'policy_not_yet_loaded'

export interface OrgAdminView {
  /** OPA would let them manage this org's people: on its roster AND a member (`manageable_orgs`). */
  admin: boolean
  /** On the org's roster in jinbe's store (addresses compared without case). */
  rostered: boolean
  why?: NotAdminWhy
}

/**
 * "Admin" as the authoritative guard answers it (`manageable_orgs`, the query requireOrgAdmin asks),
 * beside what the roster store says, and why the two differ when they do. `memberOrgs` is OPA's view
 * of membership; `roster` the store's entries for the org (lowercased); `opaRoster`, when known, the
 * copy OPA holds — a case mismatch can only be told from that copy, since the store is lowercased
 * and the feed carries every spelling.
 */
export function orgAdminView(
  email: string,
  orgId: string,
  facts: { manageable: readonly string[]; memberOrgs: readonly string[]; roster: readonly string[]; opaRoster?: readonly string[] },
): OrgAdminView {
  const admin = facts.manageable.includes(orgId)
  const address = email.toLowerCase()
  const rostered = facts.roster.some((e) => e.toLowerCase() === address)
  if (admin || !rostered) return { admin, rostered }
  if (!facts.memberOrgs.includes(orgId)) return { admin, rostered, why: 'not_a_member_per_policy' }
  if (facts.opaRoster && !facts.opaRoster.includes(email) && facts.opaRoster.some((e) => e.toLowerCase() === address)) {
    return { admin, rostered, why: 'email_case_mismatch' }
  }
  return { admin, rostered, why: 'policy_not_yet_loaded' }
}
