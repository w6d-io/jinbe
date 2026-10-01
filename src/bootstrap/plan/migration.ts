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
 *   org grant in X of a site's org-grantable group <site>-x (member of X) → <site>:x in X (the site's org role)
 *   every org (registry, memberships, org roles)             → org_sites[org] ∋ jinbe (its own org routes)
 *   the orgs each applied site's intent lists                → org_sites (what its publish reconciles to)
 *
 * An org grant of any other group has no equivalent: listed as an orphan, dropped from the policy (D4).
 */

/** Previous-model org role names on an identity and what they become (unlisted: dropped, D4). */
export const ORG_ROLE_RENAMES: Readonly<Record<string, string>> = { admin: qualified(JINBE, 'owner'), owner: qualified(JINBE, 'owner'), org_admin: qualified(JINBE, 'owner') }

export interface Migration {
  /** The org role assignments after the apply: the stored ones plus what the previous model carried. */
  assignments: OrgAssignments
  /** What was added, line by line, for the review. */
  added: Array<{ org: string; email: string; id: string; role: string; from: 'roster' | 'identity' | 'org_grant' }>
  /** org → entitled sites after the apply. */
  orgSites: Record<string, string[]>
}

export function migrationOf(inv: Inventory): Migration {
  const assignments: OrgAssignments = JSON.parse(JSON.stringify(inv.orgAssignments))
  const added: Migration['added'] = []
  const give = (org: string, email: string, id: string, role: string, from: Migration['added'][number]['from']) => {
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

  for (const [org, byAddress] of Object.entries(inv.orgGrants)) {
    for (const [address, groups] of Object.entries(byAddress)) {
      const who = byLower.get(address.toLowerCase())
      if (!who?.id || !who.organizations.includes(org)) continue
      for (const g of groups) {
        const role = siteOrgRoleOf(inv, g)
        if (role) give(org, who.email, who.id, role, 'org_grant')
      }
    }
  }

  // jinbe for EVERY org: the policy refuses an org's jinbe routes when org_sites[org] does not list it.
  // Then each site's publish reconciles org_sites to the orgs its intent lists (sites/publish.ts).
  const orgSites: Record<string, string[]> = {}
  for (const org of everyOrgOf(inv, assignments)) orgSites[org] = [JINBE]
  for (const [site, model] of Object.entries(inv.siteModels)) {
    for (const org of model.orgs) orgSites[org] = [...new Set([...(orgSites[org] ?? []), site])].sort()
  }
  return { assignments, added, orgSites }
}

/** Every org the apply must entitle to jinbe: the registry's, any a person belongs to, any holding org roles. */
export function everyOrgOf(inv: Pick<Inventory, 'organisations' | 'identities'>, assignments: OrgAssignments): string[] {
  const orgs = new Set<string>(inv.organisations)
  for (const f of inv.identities.values()) for (const o of f.organizations) if (o) orgs.add(o)
  for (const o of Object.keys(assignments)) orgs.add(o)
  return [...orgs].sort()
}

/** Orgs the migration would leave without jinbe in org_sites (must be none: the apply refuses otherwise). */
export function orgsWithoutJinbe(inv: Pick<Inventory, 'organisations' | 'identities'>, migration: Pick<Migration, 'orgSites' | 'assignments'>): string[] {
  return everyOrgOf(inv, migration.assignments).filter((o) => !(migration.orgSites[o] ?? []).includes(JINBE))
}

/** `<site>-x`, an org-grantable group of an applied site, is now that site's org role `<site>:x`. */
export function siteOrgRoleOf(inv: Pick<Inventory, 'siteModels'>, group: string): string | null {
  for (const [site, model] of Object.entries(inv.siteModels)) {
    const x = group.startsWith(`${site}-`) ? group.slice(site.length + 1) : null
    if (x && model.orgRoles[x]) return qualified(site, x)
  }
  return null
}
