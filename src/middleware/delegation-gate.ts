import type { FastifyReply, FastifyRequest } from 'fastify'
import { declaredRoute } from '../policy/declared-routes.js'
import { EVERYTHING, scopeGrants, specOf } from '../policy/catalog.js'
import { denyAudit } from '../audit/deny.js'
import { delegatedWriteBudget, productionRedirect } from './delegated-writes.js'
import { scopeRefusalFields } from '../services/permission-refusal.js'

/**
 * What a DELEGATED caller (a user acting through a client: an MCP server, a personal key) may reach.
 * Runs before every route gate; the route gates then decide the USER exactly as for a session. The
 * token can only narrow that answer:
 *
 *   1. never a permission the catalogue marks `delegable: 'never'` (policy/catalog.ts) — deletions,
 *      second-factor resets, key and client creation, approvals, the access model itself — nor `*`;
 *      the same for every org and every user, super admin included (owner decision 2026-09-29);
 *   2. never a route on the backstop list below: the machine feeds, SCIM, zones, the gateway and the
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
  // Revoking a key (personal or org) is protective and allowed (owner decision 2026-09-29, (d)):
  // listed first so the DELETE and credential rules below never refuse it.
  // Nothing else is ever deleted through a delegated token (owner decision: deletes are made by hand,
  // in the console): a site, a user, a group, a membership, a draft, a logo.
  { pattern: /^\//, methods: ['DELETE'], why: 'delete' },
  // Zones and the gateway configuration: what the platform exposes and how. Changed in the console.
  { pattern: /^\/api\/admin\/sites\/zones(\/:name)?$/, methods: ['POST', 'PUT', 'PATCH'], why: 'infrastructure' },
  { pattern: /^\/api\/admin\/gateway(\/rollback)?$/, methods: ['POST', 'PUT', 'PATCH'], why: 'infrastructure' },
  // The caller's own credentials: a token must not mint or list the keys that make tokens (org keys
  // are decided by the catalogue: org.keys:read direct, org.keys:write never).
  { pattern: /^\/api\/me\/api-keys/, methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH'], why: 'api_keys' },
  // SCIM — every method.
  { pattern: /^\/scim\/v2\//, why: 'scim' },
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

// Key revocation: the one DELETE a token may make (a leaked key can be killed from the assistant).
const KEY_REVOKE = [
  /^\/api\/me\/api-keys\/:clientId$/,
  /^\/api\/organizations\/:organizationId\/api-keys\/:clientId$/,
]

// Routes whose permission depends on the request, decided by their own guard with delegationRefusal
// (e.g. a membership change: adding is groups.members:write, removing is a deletion). The global gate
// still refuses them for the backstop and self-change rules.
const GUARD_DECIDED: readonly { method: string; pattern: RegExp }[] = [
  { method: 'PUT', pattern: /^\/api\/admin\/users\/:email\/groups$/ },
]

/** Why no delegated caller may reach this route pattern (rule 1), or null. */
export function ineligibleWhy(method: string, pattern: string): string | null {
  if (method === 'DELETE' && KEY_REVOKE.some((p) => p.test(pattern))) return null
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

  if (!permission && GUARD_DECIDED.some((r) => r.method === method && r.pattern.test(pattern))) {
    const why0 = ineligibleWhy(method, pattern)
    if (why0) return `delegation_ineligible:${why0}`
    return targetsSelf(request, method, pattern) ? 'delegation_ineligible:self_change' : null
  }
  const required = permission ?? declaredRoute(method, pattern)?.permission
  // The catalogue's verdict first: it names the permission a token may never use.
  if (required && (required === EVERYTHING || specOf(required)?.delegable === 'never')) return `delegation_ineligible:${required}`
  const why = ineligibleWhy(method, pattern)
  if (why) return `delegation_ineligible:${why}`
  if (targetsSelf(request, method, pattern)) return 'delegation_ineligible:self_change'
  const redirect = productionRedirect(method, pattern)
  if (redirect) return `delegation_refused:${redirect}`

  if (required) return scopeGrants(delegation.scopes, required) ? null : `scope_missing:${required}`
  // Revoking one of the holder's own keys needs no scope: it can only take power away (item d).
  if (method === 'DELETE' && KEY_REVOKE[0].test(pattern)) return null
  const row = declaredRoute(method, pattern)
  if (row?.class === 'public') return null
  // No permission to cover: the route answers about the caller. Reading is fine; changing is not.
  return method === 'GET' || method === 'HEAD' ? null : 'delegation_no_scope_for_write'
}

/** Global preHandler: refuses a delegated caller on any route it may not reach. */
export async function delegationGate(request: FastifyRequest, reply: FastifyReply) {
  if (request.userContext?.authVia !== 'delegated') return
  const reason = delegationRefusal(request)
  if (!reason) {
    if (!(WRITES as readonly string[]).includes(request.method.toUpperCase())) return
    const retryAfter = await delegatedWriteBudget(request)
    if (retryAfter === null) return
    denyAudit(request, 'delegated_write_rate_limited', { statusCode: 429, severity: 'warn' })
    return reply.status(429).header('Retry-After', String(retryAfter)).send({
      error: 'rate_limited',
      message: 'Too many writes through this key. Use a bulk plan for many changes at once.',
      retryAfter,
    })
  }
  denyAudit(request, reason)
  return reply.status(403).send({
    error: 'Forbidden',
    code: reason.startsWith('scope_missing') ? 'insufficient_scope' : 'delegation_refused',
    message: 'This credential acts for a user through a client and may not use this route.',
    reason,
    ...(await scopeRefusalFields(reason)),
  })
}
