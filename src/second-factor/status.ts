import { createHash } from 'node:crypto'
import { KratosSessionService, kratosSessionService } from '../services/kratos-session.service.js'
import { kratosService, type MfaMethod } from '../services/kratos.service.js'
import { secondFactorRequired } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { awaitingSecondFactor } from './awaiting.js'
import { applyAwaiting } from './awaiting-apply.js'

/**
 * `GET /api/public/second-factor` — for login-ui, right after the first factor: must THIS visitor
 * (their own Kratos session cookie, like /api/public/sites/mine) set up or prove a second factor
 * before being sent on?
 *
 *   secondFactorRequired — the policy's own answer (rbac.second_factor_required), never re-derived
 *   hasSecondFactor      — an enrolled TOTP, security key or set of backup codes (Kratos admin API)
 *   methods              — which of those are enrolled
 *   aal                  — the session's level, so the caller can tell "enrol" from "step up"
 *   awaitingGroups       — groups added while they had no second factor (awaiting.ts): they count as
 *                          required, so the person is sent to enrolment, and are applied once enrolled
 *
 * Failures are 503 with a code (`policy_unavailable`, `identity_unavailable`). login-ui then lets the
 * sign-in finish: the UI step is a convenience, and the refusal that matters happens server-side —
 * jinbe's own hook and the gateway both answer `needs_2fa` from the same rule. Blocking every sign-in
 * while OPA or Kratos is down would lock out exactly the people who have to fix it.
 *
 * Kept 15 s per identity + level — except "required and none enrolled", the state the visitor is
 * about to leave by enrolling: a cached copy of it would send them back to enrolment afterwards.
 */

export interface SecondFactorStatus {
  secondFactorRequired: boolean
  hasSecondFactor: boolean
  methods: MfaMethod[]
  aal: string
  /** Groups waiting for this person's second factor; present only when some are. */
  awaitingGroups?: string[]
}

export type StatusError = Error & { statusCode: number; code: string }
const statusError = (statusCode: number, code: string, message: string): StatusError =>
  Object.assign(new Error(message), { statusCode, code })

const TTL_MS = 15_000
const MAX_ENTRIES = 5_000
const cache = new Map<string, { at: number; status: SecondFactorStatus }>()

/** Test seam. */
export function resetSecondFactorStatusCache(): void {
  cache.clear()
}

export async function secondFactorStatus(cookieHeader: string | undefined): Promise<SecondFactorStatus> {
  const cookie = KratosSessionService.extractSessionCookie(cookieHeader)
  if (!cookie) throw statusError(401, 'unauthenticated', 'Sign in first')
  const { session } = await kratosSessionService.validateSession(cookie)
  if (!session) throw statusError(401, 'unauthenticated', 'Sign in first')

  const key = createHash('sha256').update(`${session.identityId}\0${session.email}\0${session.aal}`).digest('hex')
  const hit = cache.get(key)
  if (hit && Date.now() - hit.at < TTL_MS) return hit.status

  // The policy and Kratos are asked at once: one round trip of the slower, not their sum.
  const [policy, factors] = await Promise.allSettled([secondFactorRequired(session.email), kratosService.mfaMethodsOf(session.identityId)])
  if (policy.status === 'rejected') throw statusError(503, POLICY_UNAVAILABLE, 'The sign-in requirements cannot be checked right now')
  if (factors.status === 'rejected') throw statusError(503, 'identity_unavailable', 'Your second factors cannot be read right now')
  let required: boolean = policy.value
  const methods: MfaMethod[] = factors.value

  // Waiting groups: required now; applied as soon as a factor is enrolled (also done by the settings hook).
  let awaitingGroups: string[] = []
  try {
    awaitingGroups = (await awaitingSecondFactor.get(session.identityId))?.groups ?? []
    if (awaitingGroups.length > 0 && methods.length > 0) await applyAwaiting(session.identityId)
  } catch {
    /* the store unreadable: the policy's answer stands */
  }
  if (awaitingGroups.length > 0) required = true
  const status: SecondFactorStatus = {
    secondFactorRequired: required, hasSecondFactor: methods.length > 0, methods, aal: session.aal,
    ...(awaitingGroups.length > 0 && methods.length === 0 ? { awaitingGroups } : {}),
  }
  if (!(required && !status.hasSecondFactor)) {
    if (cache.size >= MAX_ENTRIES) cache.delete(cache.keys().next().value!)
    cache.set(key, { at: Date.now(), status })
  }
  return status
}
