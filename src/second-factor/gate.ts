import type { FastifyReply, FastifyRequest } from 'fastify'
import { env } from '../config/index.js'
import { decide } from '../authz/opa.js'
import { isPublicRoute } from '../middleware/require-auth.js'
import { denyAudit } from '../audit/deny.js'

/**
 * Server-side half of mandatory 2FA: a member of a group that must hold a second factor
 * (data.second_factor, rbac.rego § 8c) — or a caller of a route inside jinbe's own per-site 2FA
 * scope — is refused below aal2, whatever login-ui did or did not show them.
 *
 * ONE ENGINE: the question is the gateway's own (`rbac.decision` for this method + path + aal), and
 * only its `needs_2fa` answer acts here. Every other answer is left to the route's own gate, which
 * already turns "not granted" into 403 and "OPA unreachable" into 503 — so an outage never turns into
 * a 2FA refusal, and a missing permission never turns into "go and step up".
 *
 * Only a browser session is judged: it is the one credential that carries a readable level. A bearer
 * token or a ServiceAccount asserts none, so asking them to step up would loop forever
 * (`step_up_unavailable` in require-admin says the same for the R2 gate); their human was held to the
 * rule when the token was issued through login-ui. Public routes (whoami, /api/public/*) are never
 * judged, so the person can always find out what to do.
 *
 * 422, not 403: the cluster ingress replaces 401/403/404 bodies with its error page, and the console
 * needs `error` to send the person to enrol or step up (same reason as `reauth_required`).
 */

export const SECOND_FACTOR_REQUIRED = 'second_factor_required'

export async function requireSecondFactor(request: FastifyRequest, reply: FastifyReply) {
  const ctx = request.userContext
  if (!ctx || ctx.authVia !== 'session' || !ctx.email) return
  if (env.NODE_ENV === 'development' && env.DEV_BYPASS_AUTH) return
  const path = (request.url || '').split('?')[0]
  if (!path.startsWith('/api/') || isPublicRoute(path)) return

  let reason: string
  try {
    ;({ reason } = await decide({ email: ctx.email, method: request.method, path, aal: ctx.aal ?? 'aal1', client: false }))
  } catch {
    return // the route's own gate answers the outage
  }
  if (reason !== 'needs_2fa') return

  denyAudit(request, SECOND_FACTOR_REQUIRED, { statusCode: 422, severity: 'warn' })
  return reply.status(422).send({
    error: SECOND_FACTOR_REQUIRED,
    message: 'Your account must use two-step sign-in. Set up or confirm your second factor, then retry.',
    stepUp: { requiredAal: 'aal2' },
    hint: 'Complete two-step sign-in at /two-step on the sign-in site, then retry.',
  })
}
