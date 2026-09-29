import type { FastifyReply, FastifyRequest } from 'fastify'
import { declaredRoute } from '../policy/declared-routes.js'
import { EVERYTHING, scopeGrants, specOf } from '../policy/catalog.js'
import { denyAudit } from '../audit/deny.js'

/**
 * What a DELEGATED caller (a user acting through a client: an MCP server, a personal key) may reach.
 * Runs before every route gate; the route gates then decide the USER exactly as for a session. The
 * token can only narrow that answer:
 *
 *   1. never a permission the catalogue marks `delegable: 'never'` (policy/catalog.ts) — deletions,
 *      second-factor resets, key and client creation, approvals, the access model itself — nor `*`;
 *      the same for every org and every user, super admin included (owner decision 2026-09-29);
 *   2. never a route on the backstop list below: the machine feeds, SCIM, infrastructure and the
 *      caller's own credentials, which carry no catalogue permission to decide on;
 *   3. never a change to the caller's own groups or account (no self-grant);
 *   4. a route that requires a permission needs a SCOPE granting it (`scopeGrants`: exact, or a
 *      legacy alias for one release — never a wildcard);
 *   5. a token is bound to no organization: which org a route may touch is decided for the USER by
 *      the normal rules (membership, org grants, the roster) in the route's own guard;
 *   6. a route that requires no permission is reachable read-only — it answers about the caller.
 *
 * A personal key inherits its holder: its scopes are what the holder holds NOW (all of it, or the
 * subset chosen for the key), recomputed on every introspection (delegated-token.service.ts), and the
 * route gates ask the user's current rights again — a removed group stops the key at once.
 *
 * A step-up is never satisfied: the token carries no second factor (services/step-up.ts refuses
 * authVia 'delegated' as `step_up_unavailable`), so anything the catalogue marks stepUp goes to a
 * human in a browser even when it is `direct`.
 */

type Ineligible = { methods?: readonly string[]; pattern: RegExp; why: string }

const WRITES = ['POST', 'PUT', 'PATCH', 'DELETE'] as const

/**
 * The backstop: routes with no catalogue permission to decide on (their own credential, or the
 * caller's own keys) that a token must never reach. Everything a catalogue permission guards is
 * decided by its `delegable` flag instead — one list, not two.
 */
export const DELEGATION_INELIGIBLE: readonly Ineligible[] = [
  // The caller's own credentials: a token must not mint or list the keys that make tokens.
  { pattern: /^\/api\/me\/api-keys/, why: 'api_keys' },
  // SCIM, backups, databases, clusters (kubeconfigs), jobs — every method.
  { pattern: /^\/scim\/v2\//, why: 'scim' },
  { pattern: /^\/api\/(backups|backup-items|databases|database-apis|clusters|jobs)(\/|$)/, why: 'infrastructure' },
  // The policy engine's and the gateway's machine feeds.
  { pattern: /^\/api\/(opa|oathkeeper|internal)(\/|$)/, why: 'policy_data' },
  { pattern: /^\/api\/admin\/rbac\/(opal|bindings)/, why: 'policy_data' },
  // A reviewer's decision: a human decides, in a browser.
  { pattern: /^\/api\/admin\/recert\/items\//, methods: WRITES, why: 'approval' },
]

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

  const required = permission ?? declaredRoute(method, pattern)?.permission
  if (required) {
    if (required === EVERYTHING || specOf(required)?.delegable === 'never') return `delegation_ineligible:${required}`
    return scopeGrants(delegation.scopes, required) ? null : `scope_missing:${required}`
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
