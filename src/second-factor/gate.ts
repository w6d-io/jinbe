import type { FastifyReply, FastifyRequest } from 'fastify'
import { env } from '../config/index.js'
import { decide, rights, secondFactorRequired } from '../authz/opa.js'
import { isPublicRoute } from '../middleware/require-auth.js'
import { denyAudit } from '../audit/deny.js'
import { getSecondFactorGroups } from './settings.js'
import { routePermissionOf, secondFactorRefusal } from './requirements.js'

/**
 * Server-side half of mandatory 2FA: a member of a group that must hold a second factor
 * (data.second_factor, rbac.rego § 8c) is refused below aal2 on EVERY jinbe API route except the
 * exemptions listed below, whatever login-ui did or did not show them.
 *
 * ONE ENGINE: who must hold a second factor is OPA's answer (`rbac.second_factor_required`), never
 * re-derived here. It is asked per caller, not per route: jinbe's route_map in OPA describes only
 * part of its API (the admin routes are published for display, not decided on), so a per-route
 * `rbac.decision` answered not_found for them and let /api/admin/sites through at aal1. The
 * gateway's own `needs_2fa` for this route is still honoured on top (per-site 2FA of jinbe itself).
 * An unanswerable question falls through to the route's own gate, which turns "OPA unreachable" into
 * 503 — so an outage never turns into a 2FA refusal.
 *
 * Only a browser session is judged: it is the one credential that carries a readable level. A bearer
 * token or a ServiceAccount asserts none, so asking them to step up would loop forever
 * (`step_up_unavailable` in require-admin says the same for the R2 gate); their human was held to the
 * rule when the token was issued through login-ui.
 *
 * 422, not 403: the cluster ingress replaces 401/403/404 bodies with its error page, and the console
 * needs `error` to send the person to enrol or step up (same reason as `reauth_required`).
 */

export const SECOND_FACTOR_REQUIRED = 'second_factor_required'

/**
 * Every route the gate does not judge, and why. All of them answer without a session or with a
 * credential of their own (require-auth PUBLIC_ROUTES), so there is no session level to hold them to.
 * A public route added without an entry here fails the route-table test.
 */
export const SECOND_FACTOR_EXEMPT: ReadonlyArray<{ prefix: string; reason: string }> = [
  { prefix: '/api/health', reason: 'readiness probe; answers without a session' },
  { prefix: '/api/whoami', reason: 'says who is signed in, at any level; the console needs it to draw the two-step banner' },
  { prefix: '/api/telemetry', reason: 'where the browser reports, needed before and during sign-in; holds nothing private' },
  { prefix: '/api/public', reason: "login-ui and the console before sign-in completes: site branding, access-reason and the caller's own second-factor status — how a person learns they must enrol" },
  { prefix: '/api/webhooks/kratos', reason: 'Kratos after-hooks, authenticated by a shared secret, not a session' },
  { prefix: '/api/mcp', reason: 'auth-mcp introspecting tokens and exchanging keys with its ServiceAccount token, not a session' },
  { prefix: '/api/oathkeeper/rules', reason: 'the gateway fetching its rules; no session' },
  { prefix: '/api/admin/rbac/opal', reason: 'OPAL data sources, guarded by the OPAL client token, not a session' },
  { prefix: '/api/admin/rbac/bindings', reason: 'OPAL data source (identity bindings), guarded by the OPAL client token' },
  { prefix: '/api/admin/rbac/develop/', reason: 'compat path of the OPAL data sources, guarded by the OPAL client token' },
  { prefix: '/docs', reason: 'the published API description; public' },
  { prefix: '/.well-known/oauth-authorization-server', reason: 'RFC 8414 metadata MCP clients read on the Hydra host before anyone signs in; public, holds nothing private' },
  { prefix: '/oauth2/register', reason: 'MCP client registration on the Hydra host, before anyone signs in: loopback redirects only, rate limited, bound to the first consenting person' },
  { prefix: '/scim/v2', reason: "IdP provisioning with its own bearer token; no session and outside the console's API" },
]

export type SecondFactorScope = { gated: true } | { gated: false; reason: string | null }

/** Whether the gate judges a path; for an exempt one, the listed reason (null = exempt but unlisted: a bug). */
export function secondFactorScope(path: string): SecondFactorScope {
  if (path.startsWith('/api/') && !isPublicRoute(path)) return { gated: true }
  const entry = SECOND_FACTOR_EXEMPT.find((e) => path === e.prefix || path.startsWith(e.prefix.endsWith('/') ? e.prefix : `${e.prefix}/`) || path.startsWith(`${e.prefix}-`))
  return { gated: false, reason: entry?.reason ?? null }
}

/** Which rule asks this caller for a second factor on this request, or null. */
async function needsSecondFactor(email: string, method: string, path: string, aal: string): Promise<'group_sign_in' | 'site_login' | null> {
  try {
    if (aal !== 'aal2' && (await secondFactorRequired(email))) return 'group_sign_in'
  } catch {
    // Unanswerable (OPA down, or a policy that predates the rule): the route gate answers the outage.
  }
  try {
    return (await decide({ email, method, path, aal, client: false })).reason === 'needs_2fa' ? 'site_login' : null
  } catch {
    return null
  }
}

/** The caller's groups that the setting names: the explanation, never the decision (OPA made it). */
async function groupsRequiring(email: string): Promise<string[]> {
  try {
    const [held, setting] = await Promise.all([rights(email), getSecondFactorGroups()])
    return held.groups.filter((g) => setting.includes(g)).sort()
  } catch {
    return []
  }
}

export async function requireSecondFactor(request: FastifyRequest, reply: FastifyReply) {
  const ctx = request.userContext
  if (!ctx || ctx.authVia !== 'session' || !ctx.email) return
  if (env.NODE_ENV === 'development' && env.DEV_BYPASS_AUTH) return
  const path = (request.url || '').split('?')[0]
  if (!secondFactorScope(path).gated) return
  const rule = await needsSecondFactor(ctx.email, request.method, path, ctx.aal ?? 'aal1')
  if (!rule) return

  denyAudit(request, SECOND_FACTOR_REQUIRED, { statusCode: 422, severity: 'warn' })
  const requiredBecause = rule === 'group_sign_in' ? await groupsRequiring(ctx.email) : undefined
  const permission = routePermissionOf(request)
  return reply.status(422).send({
    error: SECOND_FACTOR_REQUIRED,
    message: rule === 'group_sign_in'
      ? `Your account must use two-step sign-in${requiredBecause?.length ? ` (member of ${requiredBecause.join(', ')})` : ''}. Set up or confirm your second factor, then retry.`
      : 'This service asks for two-step sign-in here. Set up or confirm your second factor, then retry.',
    stepUp: { requiredAal: 'aal2' },
    hint: 'Complete two-step sign-in at /two-step on the sign-in site, then retry.',
    ...secondFactorRefusal(rule, { permission, requiredBecause }),
  })
}
