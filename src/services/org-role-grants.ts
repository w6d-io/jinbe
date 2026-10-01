import { assignableRoles, grantVerdict, type GrantVerdict } from '../authz/opa.js'
import { redisRbacRepository } from './redis-rbac.repository.js'
import { flatten } from './grant-subset.js'
import { JINBE } from '../policy/roles.js'

/**
 * The holding rule for org roles (authz-v2-design §2.5): the policy's `rbac.delegation` verdicts —
 * `assign_verdict` for each role handed out, `unassign_verdict` for a removal, `assignable_roles` for
 * what a screen offers. ONE copy of the rule, in the policy; jinbe renders its answer. What a role
 * carries is shown from the published definition (rbac:org_roles:{svc}), never decided from it.
 * Every call throws AuthzUnavailableError when OPA cannot tell (the routes answer 503).
 */

export interface OrgRoleView {
  role: string
  permissions: string[]
  assignable: boolean
}

export type OrgRoleRefusalReason = 'unknown_role' | 'org_not_entitled' | 'grantee_not_member' | 'grant_permission_missing' | 'grant_exceeds_own'

export type OrgRoleRefusal = {
  role: string
  reason: OrgRoleRefusalReason
  /** The policy's own codes, sorted. */
  reasons: string[]
  missing?: string[]
  grantedBy?: string[]
}

/** Every org role this org may hold (jinbe's, and its entitled sites'), with the definitions. */
async function rolesOf(org: string): Promise<Array<{ svc: string; name: string; permissions: string[] }>> {
  const entitled = [JINBE, ...((await redisRbacRepository.getOrgSites())[org] ?? [])]
  const out: Array<{ svc: string; name: string; permissions: string[] }> = []
  for (const svc of [...new Set(entitled)]) {
    for (const [name, permissions] of Object.entries((await redisRbacRepository.getOrgRoles(svc)) ?? {})) out.push({ svc, name, permissions })
  }
  return out.sort((a, b) => `${a.svc}:${a.name}`.localeCompare(`${b.svc}:${b.name}`))
}

/** The org roles of `org`, each marked with whether `actor` may assign it (the policy's list). */
export async function orgRolesFor(actor: string, org: string): Promise<OrgRoleView[]> {
  const [roles, assignable] = await Promise.all([rolesOf(org), assignableRoles(actor, org)])
  const may = new Set(assignable)
  return roles.map((r) => ({ role: `${r.svc}:${r.name}`, permissions: r.permissions, assignable: may.has(`${r.svc}:${r.name}`) }))
}

/** The one reason a refusal leads with, from the policy's codes (most fundamental first). */
function leading(reasons: readonly string[]): OrgRoleRefusalReason {
  if (reasons.includes('unknown_role')) return 'unknown_role'
  if (reasons.includes('app_not_entitled')) return 'org_not_entitled'
  if (reasons.includes('grantee_not_member')) return 'grantee_not_member'
  if (reasons.includes('missing_grant_permission')) return 'grant_permission_missing'
  return 'grant_exceeds_own'
}

function refusalOf(role: string, v: GrantVerdict): OrgRoleRefusal {
  const missing = [...flatten(v.missing), ...flatten(v.missingEveryOrg).map((p) => `every organisation: ${p}`)]
  return { role, reason: leading(v.reasons), reasons: v.reasons, ...(missing.length ? { missing } : {}), ...(v.grantedBy.length ? { grantedBy: v.grantedBy } : {}) }
}

/**
 * Why each of `roles` may not be handed to `grantee` by `actor` in `org` (empty: all may).
 * `joining`: the grantee is being created into the org by this very request, so the policy cannot
 * see the membership yet — that one reason is not held against it.
 */
export async function orgRoleRefusals(
  actor: string,
  org: string,
  roles: readonly string[],
  grantee: { email: string; joining?: boolean },
): Promise<OrgRoleRefusal[]> {
  const out: OrgRoleRefusal[] = []
  for (const role of roles) {
    const v = await grantVerdict({ kind: 'assign', actor, grantee: grantee.email, org, role })
    if (v.allow) continue
    const reasons = grantee.joining ? v.reasons.filter((r) => r !== 'grantee_not_member') : v.reasons
    if (reasons.length === 0) continue
    out.push(refusalOf(role, { ...v, reasons }))
  }
  return out
}

/** Why `actor` may not take org roles away in `org` (null: they may). */
export async function orgRoleRemovalRefusal(actor: string, org: string, roles: readonly string[]): Promise<OrgRoleRefusal | null> {
  if (roles.length === 0) return null
  const v = await grantVerdict({ kind: 'unassign', actor, org })
  return v.allow ? null : refusalOf(roles.join(', '), v)
}
