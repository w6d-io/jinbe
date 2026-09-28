import type { FastifyReply, FastifyRequest } from 'fastify'
import { declaredRoute } from '../policy/declared-routes.js'
import { JINBE_BUILT_IN_ROUTES } from '../bootstrap/build-route-map.js'
import { scopeCovers } from '../services/authorization-resolution.js'
import { denyAudit } from '../audit/deny.js'

/**
 * What a DELEGATED caller (a user acting through a client: an MCP server, a personal key) may reach.
 * Runs before every route gate; the route gates then decide the USER exactly as for a session. The
 * token can only narrow that answer:
 *
 *   1. never an ineligible route — below, hard-coded, the same for every org and every user, super
 *      admin included: what mints credentials, what changes how people sign in, the org-admin
 *      roster, SCIM, backups and infrastructure, the policy and gateway data, approvals and applies,
 *      and any change to the caller's own groups or account (no self-grant);
 *   2. a route that requires a permission needs a SCOPE covering it (`covers`, never a wildcard);
 *   3. a route of one organization must be the token's organization;
 *   4. a route that requires no permission is reachable read-only — it answers about the caller.
 *
 * A step-up is never satisfied: the token carries no second factor (services/step-up.ts refuses
 * authVia 'delegated' as `step_up_unavailable`), so anything behind requireRecentMfa goes to a human
 * in a browser.
 */

type Ineligible = { methods?: readonly string[]; pattern: RegExp; why: string }

const WRITES = ['POST', 'PUT', 'PATCH', 'DELETE'] as const

export const DELEGATION_INELIGIBLE: readonly Ineligible[] = [
  // Credentials: API keys (org and personal), the OAuth2 client, key policy.
  { pattern: /^\/api\/organizations\/:organizationId\/api-key/, why: 'api_keys' },
  { pattern: /^\/api\/me\/api-keys/, why: 'api_keys' },
  // How people sign in: second-factor settings and resets, recovery and sign-in links, auth methods.
  { pattern: /^\/api\/admin\/settings\//, why: 'sign_in_settings' },
  { pattern: /^\/api\/admin\/auth\//, why: 'sign_in_settings' },
  { pattern: /^\/api\/admin\/users\/:id\/(second-factors|recovery-email|login-link)/, why: 'account_recovery' },
  // The org-admin roster.
  { pattern: /^\/api\/admin\/rbac\/org-admin-map/, why: 'org_admin_roster' },
  // SCIM, backups, databases, clusters (kubeconfigs), jobs.
  { pattern: /^\/scim\/v2\//, why: 'scim' },
  { pattern: /^\/api\/(backups|backup-items|databases|database-apis|clusters)(\/|$)/, why: 'infrastructure' },
  // The policy, the gateway rules and the data behind them; bundle import/export.
  { pattern: /^\/api\/(opa|oathkeeper|internal)(\/|$)/, why: 'policy_data' },
  { pattern: /^\/api\/admin\/rbac\/(opal|bindings|bundle|access-rules|oathkeeper)/, why: 'policy_data' },
  // Approvals and the migration cut-over: a human decides, in a browser.
  { pattern: /^\/api\/admin\/sites\/requests\/:id\/(approve|reject)$/, why: 'approval' },
  { pattern: /^\/api\/admin\/sites\/migration/, methods: WRITES, why: 'approval' },
  { pattern: /^\/api\/admin\/gateway\/(rollout|rollback)/, methods: WRITES, why: 'approval' },
  { pattern: /^\/api\/admin\/recert\/items\//, methods: WRITES, why: 'approval' },
]

/** Permissions a delegated caller can never exercise, whatever its scopes say. */
export const INELIGIBLE_PERMISSIONS: ReadonlySet<string> = new Set(['sites:apply'])

// Writes about ONE person: refused when that person is the caller (their own groups, grants,
// membership, metadata or state — any of which could hand them more than they hold).
const PERSON_WRITES = [
  /^\/api\/admin\/users\/:(id|email)(\/|$)/,
  /^\/api\/organizations\/:organizationId\/users\/:id(\/|$)/,
]

/** Why no delegated caller may reach this route pattern (rule 1), or null. */
export function ineligibleWhy(method: string, pattern: string): string | null {
  for (const rule of DELEGATION_INELIGIBLE) {
    if (rule.pattern.test(pattern) && (!rule.methods || rule.methods.includes(method))) return rule.why
  }
  return null
}

function targetsSelf(request: FastifyRequest, method: string, pattern: string): boolean {
  if (!(WRITES as readonly string[]).includes(method)) return false
  if (!PERSON_WRITES.some((p) => p.test(pattern))) return false
  const params = (request.params ?? {}) as Record<string, string | undefined>
  const uc = request.userContext
  const target = (params.id ?? params.email ?? '').toLowerCase()
  return target !== '' && (target === uc?.id?.toLowerCase() || target === uc?.email?.toLowerCase())
}

/** The path param naming the route's organization, when it is one organization's. */
export function orgParamOf(method: string, pattern: string): string | null {
  const row = JINBE_BUILT_IN_ROUTES.find((r) => r.method === method && r.path === pattern && r.org_param)
  if (row?.org_param) return row.org_param
  return pattern.startsWith('/api/organizations/:organizationId') ? 'organizationId' : null
}

/**
 * Why a delegated caller may not reach this route, or null. `permission` overrides the published
 * route table (a guard that knows its own permission passes it).
 */
export function delegationRefusal(request: FastifyRequest, permission?: string): string | null {
  const delegation = request.userContext?.delegation
  if (request.userContext?.authVia !== 'delegated') return null
  if (!delegation) return 'delegation_missing'
  const method = request.method.toUpperCase()
  const pattern = request.routeOptions?.url ?? (request.url || '').split('?')[0]

  const why = ineligibleWhy(method, pattern)
  if (why) return `delegation_ineligible:${why}`
  if (targetsSelf(request, method, pattern)) return 'delegation_ineligible:self_change'

  const orgParam = orgParamOf(method, pattern)
  if (orgParam) {
    const org = ((request.params ?? {}) as Record<string, string | undefined>)[orgParam]
    if (org !== delegation.org) return 'delegation_other_org'
  }

  const required = permission ?? declaredRoute(method, pattern)?.permission
  if (required) {
    if (INELIGIBLE_PERMISSIONS.has(required)) return `delegation_ineligible:${required}`
    return scopeCovers(delegation.scopes, required) ? null : `scope_missing:${required}`
  }
  const row = declaredRoute(method, pattern)
  if (row?.class === 'public') return null
  // No permission to cover: the route answers about the caller. Reading is fine; changing is not.
  return method === 'GET' || method === 'HEAD' ? null : 'delegation_no_scope_for_write'
}

/** Global preHandler: refuses a delegated caller on any route it may not reach. */
export async function delegationGate(request: FastifyRequest, reply: FastifyReply) {
  if (request.userContext?.authVia !== 'delegated') return
  const reason = delegationRefusal(request)
  if (!reason) return
  denyAudit(request, reason)
  return reply.status(403).send({
    error: 'Forbidden',
    code: reason.startsWith('scope_missing') ? 'insufficient_scope' : 'delegation_refused',
    message: 'This credential acts for a user through a client and may not use this route.',
    reason,
  })
}
