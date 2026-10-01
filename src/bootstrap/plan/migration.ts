import { JINBE, qualified } from '../../policy/roles.js'
import { QUALIFIED_ROLE, type OrgAssignments } from '../../services/org-roles.repository.js'
import type { Inventory } from './inventory.js'

/**
 * What the apply carries over from the previous model into the new one — proposed by the plan,
 * applied by `--apply` (the same function both times, so the reviewed list IS what is written):
 *
 *   roster admin of X who is a member of X        → jinbe:owner in X
 *   metadata_admin.organization_roles admin/owner → jinbe:owner in X (a member of X)
 *   an org role already `svc:role` on the identity → kept, in rbac:org_assignments
 *   org_service_map[X] ∋ site                      → org_sites[X] ∋ site (jinbe and kuma dropped)
 *
 * Org grants (groups handed out inside an org) have no equivalent until the sites carry org roles
 * (wave V4): listed as orphans, dropped from the policy (D4).
 */

/** Previous-model org role names on an identity and what they become (unlisted: dropped, D4). */
export const ORG_ROLE_RENAMES: Readonly<Record<string, string>> = { admin: qualified(JINBE, 'owner'), owner: qualified(JINBE, 'owner'), org_admin: qualified(JINBE, 'owner') }

export interface Migration {
  /** The org role assignments after the apply: the stored ones plus what the previous model carried. */
  assignments: OrgAssignments
  /** What was added, line by line, for the review. */
  added: Array<{ org: string; email: string; id: string; role: string; from: 'roster' | 'identity' }>
  /** org → entitled sites after the apply. */
  orgSites: Record<string, string[]>
}

export function migrationOf(inv: Inventory): Migration {
  const assignments: OrgAssignments = JSON.parse(JSON.stringify(inv.orgAssignments))
  const added: Migration['added'] = []
  const give = (org: string, email: string, id: string, role: string, from: 'roster' | 'identity') => {
    const members = (assignments[org] ??= {})
    const roles = (members[id] ??= [])
    if (roles.includes(role)) return
    roles.push(role)
    roles.sort()
    added.push({ org, email, id, role, from })
  }
  const byLower = new Map([...inv.identities.entries()].map(([email, f]) => [email.toLowerCase(), { email, ...f }]))

  for (const [org, admins] of Object.entries(inv.orgAdmins)) {
    for (const address of admins) {
      const who = byLower.get(address.toLowerCase())
      if (who?.id && who.organizations.includes(org)) give(org, who.email, who.id, qualified(JINBE, 'owner'), 'roster')
    }
  }
  for (const [email, f] of inv.identities) {
    if (!f.id) continue
    for (const [org, roles] of Object.entries(f.organizationRoles)) {
      if (!f.organizations.includes(org)) continue
      for (const role of roles) {
        const to = QUALIFIED_ROLE.test(role) ? role : ORG_ROLE_RENAMES[role]
        if (to) give(org, email, f.id, to, 'identity')
      }
    }
  }

  const orgSites: Record<string, string[]> = {}
  const sites = new Set(inv.sites)
  for (const [org, list] of Object.entries(inv.orgSites)) orgSites[org] = [...list]
  for (const [org, services] of Object.entries(inv.orgServices)) {
    const entitled = services.filter((s) => sites.has(s))
    if (entitled.length) orgSites[org] = [...new Set([...(orgSites[org] ?? []), ...entitled])].sort()
  }
  return { assignments, added, orgSites }
}
