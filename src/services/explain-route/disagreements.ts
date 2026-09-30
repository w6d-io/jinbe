import type { OrgAdminView } from '../org-admin.js'
import type { RouteRule } from '../redis-rbac.repository.js'
import type { PolicyExplain } from './explain-route.service.js'

/**
 * Where two surfaces answer one question differently — each a bug or a lag somebody should see, not
 * a verdict: the guard's answer is the one the caller gets.
 */
export interface Disagreement {
  kind:
    | 'opa_vs_guard'
    | 'explain_vs_decision'
    | 'roster_redis_vs_opa'
    | 'user_access_vs_guard'
    | 'org_admin_guards'
    | 'route_map_redis_vs_opa'
  between: [string, string]
  detail: string
}

export interface DisagreementFacts {
  opaAllow: boolean | null
  opaReason: string | null
  guardAllowed: boolean
  guardDecidedBy: string
  /** Holds the route's permission across the platform (the guards' staff fallback). */
  holder: boolean
  policy: PolicyExplain | null
  decisionFromPolicy: { allow?: boolean; reason?: string } | null
  org: string | null
  redisRostered: boolean | null
  opaRostered: boolean | null
  userAccess: OrgAdminView | null
  /** requireOrgAdmin's answer: super_admin ∨ platform holder ∨ manageable_orgs. */
  orgAdminFamily: boolean | null
  storedRows: RouteRule[] | null
  matchingRules: RouteRule[]
  stepUpBy: string[]
}

const why = (reason: string | null, stepUpBy: string[]) =>
  reason === 'needs_2fa' && stepUpBy.length > 0 ? `needs_2fa (${stepUpBy.join(', ')})` : reason ?? 'unknown'

export function findDisagreements(f: DisagreementFacts): Disagreement[] {
  const out: Disagreement[] = []

  // The gateway and jinbe's guard. A platform holder passing jinbe while OPA refuses is by design
  // (the staff fallback), and said so; anything else is drift.
  if (f.opaAllow !== null && f.opaAllow !== f.guardAllowed) {
    const byDesign = !f.opaAllow && f.guardAllowed && f.holder
    out.push({
      kind: 'opa_vs_guard',
      between: ['rbac.decision', f.guardDecidedBy],
      detail: f.opaAllow
        ? `OPA allows, but ${f.guardDecidedBy} refuses.`
        : byDesign
          ? `OPA refuses (${why(f.opaReason, f.stepUpBy)}), but jinbe lets a platform holder of the route's permission through; the gateway would still refuse this caller.`
          : `OPA refuses (${why(f.opaReason, f.stepUpBy)}), but the guards let it through.`,
    })
  }

  // rbac.explain replays nothing, so it must agree with rbac.decision; if not, the policy is torn.
  if (f.policy && f.decisionFromPolicy && (f.policy.allow !== f.decisionFromPolicy.allow || f.policy.reason !== f.decisionFromPolicy.reason)) {
    out.push({
      kind: 'explain_vs_decision',
      between: ['rbac.explain', 'rbac.decision'],
      detail: `rbac.explain says ${f.policy.allow ? 'allow' : 'refuse'} (${f.policy.reason}), rbac.decision ${f.decisionFromPolicy.allow ? 'allow' : 'refuse'} (${f.decisionFromPolicy.reason}).`,
    })
  }

  if (f.org && f.redisRostered !== null && f.opaRostered !== null && f.redisRostered !== f.opaRostered) {
    out.push({
      kind: 'roster_redis_vs_opa',
      between: ['redis rbac:org_admins', 'data.org_admin_map'],
      detail: f.redisRostered
        ? `On org '${f.org}'s roster in jinbe, not in OPA's copy: OPAL has not delivered it yet, or the addresses differ in case.`
        : `On org '${f.org}'s roster in OPA's copy, no longer in jinbe's: OPAL has not delivered the removal yet.`,
    })
  }

  // get_user_access's `admin` is manageable_orgs; a guard refusing an admin (or letting in a
  // non-admin on an admin route) is exactly the bug that made the flag misleading.
  if (f.org && f.userAccess && f.userAccess.admin && !f.guardAllowed) {
    out.push({
      kind: 'user_access_vs_guard',
      between: ['get_user_access.admin', f.guardDecidedBy],
      detail: `get_user_access shows admin of '${f.org}', but ${f.guardDecidedBy} refuses: ${why(f.opaReason, f.stepUpBy)}.`,
    })
  }
  if (f.org && f.userAccess && f.userAccess.rostered && !f.userAccess.admin) {
    out.push({
      kind: 'user_access_vs_guard',
      between: ['redis rbac:org_admins', 'rbac.delegation.manageable_orgs'],
      detail: `Rostered for '${f.org}' but not an admin per policy: ${f.userAccess.why}.`,
    })
  }

  // The two org guard families: requireOrgAdmin (super_admin ∨ holder ∨ manageable_orgs) and the
  // decision-based ones. Different answers for one caller in one org are two rules for one question.
  if (f.org && f.orgAdminFamily !== null && f.opaAllow !== null) {
    const decisionFamily = f.opaAllow || f.holder
    if (f.orgAdminFamily !== decisionFamily) {
      out.push({
        kind: 'org_admin_guards',
        between: ['requireOrgAdmin', 'requireServiceAdmin / requireOrgPermission'],
        detail: f.orgAdminFamily
          ? `requireOrgAdmin would let them into '${f.org}', the decision-based guards refuse (${why(f.opaReason, f.stepUpBy)}).`
          : `The decision-based guards let them into '${f.org}' on this route, requireOrgAdmin would refuse.`,
      })
    }
  }

  if (f.storedRows !== null) {
    const stored = f.storedRows.length > 0
    const loaded = f.matchingRules.some((r) => f.storedRows!.some((s) => s.path === r.path && s.method === r.method))
    if (stored !== loaded && (stored || f.matchingRules.length > 0)) {
      out.push({
        kind: 'route_map_redis_vs_opa',
        between: ['redis rbac:route_map:jinbe', 'data.route_map'],
        detail: stored
          ? 'jinbe publishes rows for this route but OPA matched none of them: OPAL has not delivered the route map, or a wider row wins.'
          : 'OPA matched rows that jinbe no longer publishes for this pattern.',
      })
    }
  }

  return out
}
