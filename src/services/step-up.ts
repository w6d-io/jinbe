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
}

/** Fail-closed: an unknown level or an unknown proof time is not fresh. */
export function secondFactorIsFresh(actor: StepUpState, now: number = Date.now()): boolean {
  if (actor.aal !== 'aal2') return false
  if (!actor.secondFactorAt) return false
  const provenAt = new Date(actor.secondFactorAt).getTime()
  if (!provenAt || Number.isNaN(provenAt)) return false
  return now - provenAt <= STEP_UP_MAX_AGE_MS
}

/** Why the gate refused, so each caller can say it in its own words. */
export function stepUpFailure(actor: StepUpState, now: number = Date.now()): 'absent' | 'stale' | null {
  if (secondFactorIsFresh(actor, now)) return null
  return actor.aal === 'aal2' && actor.secondFactorAt ? 'stale' : 'absent'
}
