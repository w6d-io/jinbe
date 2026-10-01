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
    | 'route_map_redis_vs_opa'
  between: [string, string]
  detail: string
}

export interface DisagreementFacts {
  opaAllow: boolean | null
  opaReason: string | null
  guardAllowed: boolean
  guardDecidedBy: string
  policy: PolicyExplain | null
  decisionFromPolicy: { allow?: boolean; reason?: string } | null
  storedRows: RouteRule[] | null
  matchingRules: RouteRule[]
  stepUpBy: string[]
}

const why = (reason: string | null, stepUpBy: string[]) =>
  reason === 'needs_2fa' && stepUpBy.length > 0 ? `needs_2fa (${stepUpBy.join(', ')})` : reason ?? 'unknown'

export function findDisagreements(f: DisagreementFacts): Disagreement[] {
  const out: Disagreement[] = []

  // The gateway and jinbe's guard ask one rule; different answers are drift.
  if (f.opaAllow !== null && f.opaAllow !== f.guardAllowed) {
    out.push({
      kind: 'opa_vs_guard',
      between: ['rbac.decision', f.guardDecidedBy],
      detail: f.opaAllow
        ? `OPA allows, but ${f.guardDecidedBy} refuses.`
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
