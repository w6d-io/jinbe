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
