import type { RouteRule } from '../services/redis-rbac.repository.js'

/**
 * A route rule's `org_param` names the `:param` segment of its path that carries the org id.
 *
 * Mirrors `rule_org` in opal-policies org.rego: the param must appear exactly once, or the policy
 * cannot read the org id and denies every request on the route — fail-closed, but silent. So a rule
 * that would do that is refused where its author can still be told why.
 */
export function orgParamProblem(rule: Pick<RouteRule, 'method' | 'path' | 'org_param'>): string | null {
  if (rule.org_param === undefined) return null
  if (typeof rule.org_param !== 'string' || rule.org_param === '') {
    return `org_param of ${rule.method} ${rule.path} must be a non-empty string`
  }
  const count = rule.path.split('/').filter((segment) => segment === `:${rule.org_param}`).length
  if (count === 0) return `org_param '${rule.org_param}' of ${rule.method} ${rule.path} is not a :param of the path`
  if (count > 1) return `org_param '${rule.org_param}' of ${rule.method} ${rule.path} appears more than once in the path`
  return null
}

/** 400 before any write when a rule's org_param cannot be read by the policy. */
export function assertOrgParams(service: string, rules: readonly RouteRule[]): void {
  const problems = rules.map(orgParamProblem).filter((p): p is string => p !== null)
  if (problems.length > 0) {
    throw Object.assign(new Error(`Route map for '${service}' rejected — ${problems.join('; ')}`), { statusCode: 400 })
  }
}
