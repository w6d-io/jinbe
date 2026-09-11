/**
 * How recently the actor proved a SECOND factor — the one question both privileged-change gates
 * ask, kept in one place so they cannot answer it differently.
 *
 * The clock is the aal2 method's own `completed_at`, never the session's `authenticated_at`.
 * `authenticated_at` is stamped by the FIRST factor, and an aal2 step-up does not move it —
 * measured on a live session: password 08:17:06, TOTP 08:17:45, `authenticated_at` still 08:17:06.
 * A gate reading it keeps refusing a factor that was just proven, and no amount of re-verifying
 * clears the refusal.
 */

export const STEP_UP_MAX_AGE_MS = 15 * 60 * 1000

export type StepUpState = {
  aal?: string
  secondFactorAt?: Date | string | null
  /**
   * How the caller was proven. Only a Kratos session carries a second factor this service can read;
   * a bearer token asserts none, so re-verifying would not change the answer and must not be asked
   * for — an operator sent to prove a factor that is never read loops forever.
   */
  authVia?: 'session' | 'bearer' | 'machine' | 'dev'
}

/** Fail-closed: an unknown level or an unknown proof time is not fresh. */
export function secondFactorIsFresh(actor: StepUpState, now: number = Date.now()): boolean {
  if (!canProveSecondFactor(actor)) return false
  if (actor.aal !== 'aal2') return false
  if (!actor.secondFactorAt) return false
  const provenAt = new Date(actor.secondFactorAt).getTime()
  if (!provenAt || Number.isNaN(provenAt)) return false
  return now - provenAt <= STEP_UP_MAX_AGE_MS
}

/**
 * Whether a second factor is even readable for this caller. Absent `authVia` means a context built
 * before the field existed, which was always a session.
 */
export function canProveSecondFactor(actor: StepUpState): boolean {
  return actor.authVia === undefined || actor.authVia === 'session' || actor.authVia === 'dev'
}

/**
 * Why the gate refused, so each caller can say it in its own words — and so a refusal that a
 * step-up CANNOT lift is never dressed up as one that can.
 */
export function stepUpFailure(
  actor: StepUpState,
  now: number = Date.now(),
): 'absent' | 'stale' | 'unprovable' | null {
  if (!canProveSecondFactor(actor)) return 'unprovable'
  if (secondFactorIsFresh(actor, now)) return null
  return actor.aal === 'aal2' && actor.secondFactorAt ? 'stale' : 'absent'
}
