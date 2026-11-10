import type { Handler } from './schemas.js'

/**
 * Impersonation at the gateway (src/impersonation): a second `cookie_session` authenticator, placed
 * BEFORE the gate's first one, that asks jinbe instead of Kratos — and only for requests carrying the
 * impersonation cookie.
 *
 * Oathkeeper merges a rule's handler config over the global one (arrays replaced), and a
 * cookie_session whose `only` cookies are all absent is "not responsible": ordinary traffic falls
 * through to the gate's own authenticators untouched. With the cookie present this one answers, and
 * any answer but 200 is the gateway's 401 — it never falls back to the administrator's own session.
 * `preserve_path` keeps the check URL's path, `preserve_host` tells jinbe which site is browsed
 * (X-Forwarded-Host); the answer has the shape of a Kratos session, so the gate's payload and header
 * templates read it as they read any other.
 *
 * Added at render time, never stored in the intent: a gate's own authenticators stay what the editor
 * wrote, and a preset gate stays a preset gate.
 */

export interface PlatformImpersonation {
  /** The impersonation cookie's name (IMPERSONATION_COOKIE_NAME). */
  cookie: string
  /** Where the gateway asks, in the cluster (IMPERSONATION_CHECK_URL). */
  checkUrl: string
}

export function impersonationAuthenticator(p: PlatformImpersonation): Handler {
  return {
    handler: 'cookie_session',
    config: {
      check_session_url: p.checkUrl,
      only: [p.cookie],
      preserve_path: true,
      preserve_host: true,
      subject_from: 'identity.id',
      extra_from: '@this',
    },
  }
}

/**
 * The authenticators a gate is rendered with: its own, with the impersonation one right before its
 * first `cookie_session`. A gate that takes no session cookie (tokens only, anyone, pre-flight) is
 * left alone, and so is every gate of a platform without impersonation.
 */
export function withImpersonation(authenticators: Handler[], p: PlatformImpersonation | undefined): Handler[] {
  if (!p) return authenticators
  const first = authenticators.findIndex((a) => a.handler === 'cookie_session')
  if (first < 0) return authenticators
  return [...authenticators.slice(0, first), impersonationAuthenticator(p), ...authenticators.slice(first)]
}
