import { FastifyRequest, FastifyReply } from 'fastify'
import { env } from '../config/env.js'
import { STEP_UP_MAX_AGE_MS, canProveSecondFactor, secondFactorIsFresh } from '../services/step-up.js'
import type { UserRbacInfo } from '../services/authorization-resolution.js'
import { denyAudit } from '../audit/deny.js'
import { ROLES } from '../policy/roles.js'
import { keyStepUpVerdict } from './delegated-step-up.js'
import { routePermissionOf, secondFactorRefusal } from '../second-factor/requirements.js'

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
  const verdict = stepUp.authVia === 'delegated' ? keyStepUpVerdict(request) : null
  if (verdict?.ok) return
  if (!secondFactorIsFresh(stepUp)) {
    const unprovable = !canProveSecondFactor(stepUp)
    // Emit the currently-silent step-up denial (A2).
    denyAudit(request, unprovable ? 'step_up_unavailable' : 'reauth_required', { statusCode: 422, severity: 'warn' })
    // Which rule refused, and on which permission, so the console and the MCP can say so.
    const permission = routePermissionOf(request)
    if (unprovable) {
      const keyReason = verdict && !verdict.ok && verdict.reason !== 'not_delegated' ? verdict.reason : undefined
      return reply.status(422).send({
        error: 'step_up_unavailable',
        message:
          'This action requires a second factor proven in a browser session. The credential you presented cannot carry one.',
        hint: keyReason
          ? ((request.userContext?.delegation?.kind === 'personal' ? KEY_HINTS : GRANT_HINTS)[keyReason] ?? KEY_HINTS.default)
          : 'Sign in to the console in a browser and retry there.',
        ...secondFactorRefusal('step_up', { permission, keyReason }),
      })
    }
    return reply.status(422).send({
      error: 'reauth_required',
      message:
        'This action requires a recent second factor. Re-verify two-factor authentication (TOTP) within the last 15 minutes and retry.',
      stepUp: { requiredAal: 'aal2', maxAgeMinutes: STEP_UP_MAX_AGE_MS / 60000 },
      hint: 'Re-verify at /login?aal=aal2&refresh=true, then retry.',
      ...secondFactorRefusal('step_up', { permission }),
    })
  }
}

/** Why a personal key's creation-time second factor did not stand in (delegated-step-up.ts), for a person. */
const KEY_HINTS: Record<string, string> = {
  not_personal_key: 'Only a personal key can stand on a second factor; do this in the console in a browser.',
  step_up_actions_off: 'This key was created with protected actions switched off; do this in the console, or create a key that allows them.',
  no_key_step_up: 'This key carries no second-factor proof; create a new personal key after signing in with your second factor.',
  key_step_up_expired: 'The second factor this key stands on is older than 30 days; create a new personal key, or do this in the console.',
  not_allowed_here: 'A key may not stand in for the second factor on this action; do this in the console in a browser.',
  default: 'Sign in to the console in a browser and retry there.',
}

/**
 * The same reasons for an OAuth grant, which stands on the second factor proven at consent (the OAuth
 * branch reuses the key reasons; its window is the MCP setting oauth.protectedActionsHours).
 */
const GRANT_HINTS: Record<string, string> = {
  step_up_actions_off: 'Protected actions were not allowed when this assistant was connected; reconnect it and allow them, or do this in the console.',
  no_key_step_up: 'This connection carries no second-factor proof; reconnect the assistant after signing in with your second factor.',
  key_step_up_expired: 'The second factor proven when this assistant was connected is too old for protected actions; reconnect it, or do this in the console.',
  not_allowed_here: KEY_HINTS.not_allowed_here,
}
