import { FastifyRequest, FastifyReply } from 'fastify'
import { env } from '../config/env.js'
import { isSuperAdmin } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { STEP_UP_MAX_AGE_MS, canProveSecondFactor, secondFactorIsFresh } from '../services/step-up.js'
import { enforcing } from '../policy/declared-routes.js'
import type { UserRbacInfo } from '../services/authorization-resolution.js'
import { denyAudit } from '../audit/deny.js'
import { ROLES } from '../policy/roles.js'
import { EVERYTHING } from '../policy/catalog.js'
import { keyStepUpVerdict } from './delegated-step-up.js'
import { missingPermissionFields } from '../services/permission-refusal.js'

declare module 'fastify' {
  interface FastifyRequest {
    rbacInfo?: UserRbacInfo
  }
}

/**
 * What local development (DEV_BYPASS_AUTH) is stamped with: the staff role DEV_ROLE names, its group
 * and its permissions — so the dev bypass exercises the real matrix rather than a catch-all.
 */
export function devRights(): { groups: string[]; roles: string[]; permissions: string[] } {
  const role = ROLES[env.DEV_ROLE]
  return { groups: [role.group], roles: [env.DEV_ROLE], permissions: [...role.permissions] }
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
  // A personal MCP key may stand on the second factor proven when it was created, for the few step-up
  // actions a key may do (owner decision 2026-09-29, item c; delegated-step-up.ts).
  if (stepUp.authVia === 'delegated' && keyStepUpVerdict(request).ok) return
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

/** What the route table says a super-admin-only route requires: the wildcard, which no scope covers. */
export { EVERYTHING }

/**
 * A global role carrying `*` (OPA `rbac.super_admin`) — for what nobody short of a super admin may
 * touch (`config.permission: '*'`). Fail-closed: OPA unreachable answers 503, never an allow.
 */
export const requireGlobalSuperAdmin = enforcing(async function requireGlobalSuperAdmin(request: FastifyRequest, reply: FastifyReply) {
  const email = request.userContext?.email
  const subject = request.userContext?.id
  if (!email || email === 'unknown' || !subject || subject === 'unknown') {
    return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
  }
  let superAdmin: boolean
  if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
    request.rbacInfo = { email, ...devRights() }
    superAdmin = request.rbacInfo.permissions.includes(EVERYTHING)
  } else {
    try {
      superAdmin = await isSuperAdmin(email)
    } catch (err) {
      request.log.warn({ email, err: (err as Error).message }, 'OPA could not say whether the caller is a super admin — refusing rather than guessing')
      return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: 'Unable to verify authorization. Please try again later.' })
    }
  }
  if (!superAdmin) {
    denyAudit(request, 'not_super_admin')
    return reply.status(403).send({ error: 'Forbidden', code: 'permission_required', message: 'Super admin access required', ...(await missingPermissionFields([EVERYTHING])) })
  }
}, EVERYTHING)
