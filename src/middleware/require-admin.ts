import { FastifyRequest, FastifyReply } from 'fastify'
import { env } from '../config/env.js'
import { holds, rights } from '../authz/opa.js'
import { STEP_UP_MAX_AGE_MS, canProveSecondFactor, secondFactorIsFresh } from '../services/step-up.js'
import { enforcing } from '../policy/declared-routes.js'
import type { UserRbacInfo } from '../services/authorization-resolution.js'
import { denyAudit } from '../audit/deny.js'

/** Reading the administration API. `admin:write` does not imply it — a role needing both carries both. */
const READ_ADMIN = 'admin:read'
/** Writing the administration API. Verbs do not imply one another, so this is not `admin:read`. */
const WRITE_ADMIN = 'admin:write'
const SITES_APPLY = 'sites:apply'

declare module 'fastify' {
  interface FastifyRequest {
    rbacInfo?: UserRbacInfo
  }
}

/** What local development is stamped with: the coarse pair every administration gate refines. */
const DEV_RIGHTS = { groups: ['platform-admin'], roles: ['platform-admin'], permissions: [READ_ADMIN, WRITE_ADMIN] }

/**
 * A gate on one platform permission, asked of OPA — what the caller holds in jinbe, global roles
 * included (`rbac.user_info`), the same resolution the gateway decides with.
 *
 * "Holds nothing" is a decision and answers 403; "cannot be established" is an outage and answers
 * 503. Letting the second pass as the first would turn every failure of the engine into a permission
 * somebody would go and ask about.
 */
function platformGate(required: string, denyReason: string, message: string, dev: string[] = DEV_RIGHTS.permissions) {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const email = request.userContext?.email
    const subject = request.userContext?.id
    if (!email || email === 'unknown' || !subject || subject === 'unknown') {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    }

    if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
      request.log.warn({ email, required }, '⚠️  DEV MODE: authorization bypassed')
      request.rbacInfo = { email, ...DEV_RIGHTS, permissions: dev }
      return
    }

    let rbacInfo: UserRbacInfo
    try {
      rbacInfo = { email, ...(await rights(email)) }
    } catch (err) {
      request.log.warn({ email, err: (err as Error).message }, 'OPA could not say what the caller holds — refusing rather than guessing')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    }
    request.rbacInfo = rbacInfo

    if (!holds(rbacInfo.permissions, required)) {
      request.log.warn({ email, subject, permissions: rbacInfo.permissions, required }, 'Access denied — missing the permission this API requires')
      denyAudit(request, denyReason)
      return reply.status(403).send({ error: 'Forbidden', message })
    }
  }
}

/**
 * Step-up gate (R2), reused by the org-admin roster endpoint: the actor must
 * hold a SECOND FACTOR proven within the last 15 minutes — measured on the aal2
 * method's own completed_at, not the session's first-factor authenticated_at.
 * Returns 422 reauth_required (status pinned to 422 so cluster ingress does not
 * strip the body) when the factor is absent or stale. Fail-closed on missing
 * AAL/timestamp. The dev-bypass identity is stamped AAL2, so local dev passes.
 */
export async function requireRecentMfa(request: FastifyRequest, reply: FastifyReply) {
  const stepUp = {
    aal: request.userContext?.aal,
    secondFactorAt: request.userContext?.secondFactorAt,
    authVia: request.userContext?.authVia,
  }
  if (!secondFactorIsFresh(stepUp)) {
    const unprovable = !canProveSecondFactor(stepUp)
    // Emit the currently-silent step-up denial (A2).
    denyAudit(request, unprovable ? 'step_up_unavailable' : 'reauth_required', { statusCode: 422, severity: 'warn' })
    if (unprovable) {
      return reply.status(422).send({
        error: 'step_up_unavailable',
        message:
          'This action requires a second factor proven in a browser session. The credential you presented cannot carry one.',
        hint: 'Sign in to the console in a browser and retry there.',
      })
    }
    return reply.status(422).send({
      error: 'reauth_required',
      message:
        'This action requires a recent second factor. Re-verify two-factor authentication (TOTP) within the last 15 minutes and retry.',
      stepUp: { requiredAal: 'aal2', maxAgeMinutes: STEP_UP_MAX_AGE_MS / 60000 },
      hint: 'Re-verify at /login?aal=aal2&refresh=true, then retry.',
    })
  }
}

// The fixed gates, marked with what they require so the published route table is read off the
// guard rather than written beside it. Two spellings of one rule are two rules.
export const requireAdmin = enforcing(
  platformGate(READ_ADMIN, 'not_admin', 'Admin or superadmin access required'),
  READ_ADMIN,
)
export const requireSuperAdmin = enforcing(
  platformGate(WRITE_ADMIN, 'not_super_admin', 'Super admin access required to modify user groups'),
  WRITE_ADMIN,
)

/**
 * Changing what the gateway serves through the Sites API — apply, rollback, pause, delete, restore,
 * approving a request, the migration cut-over (owner decision: "admin:write drafts and requests;
 * super_admin applies"). Held through `*` (super_admin) or `sites:apply` itself; an administrator with
 * `admin:write` only may draft, save and ask. Pair with requireRecentMfa.
 */
export const requireSitesApply = enforcing(
  platformGate(
    SITES_APPLY,
    'not_super_admin',
    'Only a super admin can change what the gateway serves; send a request instead',
    [...DEV_RIGHTS.permissions, SITES_APPLY],
  ),
  SITES_APPLY,
)
