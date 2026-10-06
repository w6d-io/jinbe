import type { OrgAssignments } from './org-roles.repository.js'

/**
 * An organisation's owners hold each site's owner role there (the intent's `organizations.ownerRole`,
 * rbac:org_owner_roles): `jinbe:owner` in an org → `<site>:<ownerRole>` in that org, for every site
 * with organizations on that serves it (org_sites). Derived where the policy data is assembled — the
 * OPAL bindings feed and the plan — never stored: naming an owner, serving a site or changing the
 * owner role moves it at once, and nothing is left behind when one of them goes.
 *
 * Real in the data the gateway decides on (data.bindings.org_assignments), so the holding rule
 * (rbac.delegation assign_verdict) lets an owner hand out the site's lesser org roles from day one,
 * and the org headers carry it.
 *
 * NO IMPORTS of runtime modules: the plan (authz/model/dataset.ts) loads it.
 */

export const OWNER = 'jinbe:owner'

export function withOwnerRoles(
  assignments: OrgAssignments,
  ownerRoles: Readonly<Record<string, string>>,
  orgSites: Readonly<Record<string, readonly string[]>>,
): OrgAssignments {
  const out: OrgAssignments = {}
  for (const [org, members] of Object.entries(assignments)) {
    const derived = (orgSites[org] ?? []).filter((site) => ownerRoles[site]).map((site) => `${site}:${ownerRoles[site]}`)
    out[org] = Object.fromEntries(Object.entries(members).map(([subject, roles]) => [
      subject,
      roles.includes(OWNER) && derived.length ? [...new Set([...roles, ...derived])].sort() : roles,
    ]))
  }
  return out
}
