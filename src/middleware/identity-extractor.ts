import { FastifyRequest, FastifyReply } from 'fastify'
import {
  kratosSessionService,
  KratosSessionService,
  ValidatedSession,
} from '../services/kratos-session.service.js'
import { env } from '../config/index.js'
import {
  k8sTokenReviewService,
  type K8sServiceAccountPrincipal,
} from '../services/k8s-token-review.service.js'
import { oidcBearerService } from '../services/oidc-bearer.service.js'

/**
 * User context derived from the validated Kratos session.
 */
export interface UserContext {
  email: string
  id: string
  name: string
  sessionId?: string
  expiresAt?: Date
  // Second-factor state for the privileged-action step-up gate (R2).
  aal?: string
  authenticatedAt?: Date
  secondFactorAt?: Date | null
  // How the caller was proven. Only a session carries a readable second factor.
  authVia?: 'session' | 'bearer' | 'machine' | 'dev'
  /**
   * The organisations the caller's token asserts, when the deployment reads them from the token
   * rather than from this service's own model. Empty in `local` mode, where the model answers —
   * never a merge of the two, because two authorities on one question cannot be told apart when
   * they disagree.
   */
  organisations?: readonly string[]
}

declare module 'fastify' {
  interface FastifyRequest {
    userContext?: UserContext
    validatedSession?: ValidatedSession
    sessionError?: string
    /**
     * Set when the caller is a machine (Kubernetes ServiceAccount) rather than
     * a human session. Handlers that must refuse machine callers — or that
     * want the real SA name in an audit record — read this; authorization
     * itself runs off userContext.email exactly as for humans.
     */
    machine?: K8sServiceAccountPrincipal
  }
}

/** `Authorization: Bearer <token>` → token, or null. */
function extractBearerToken(header?: string): string | null {
  if (!header) return null
  const match = /^Bearer\s+(.+)$/i.exec(header.trim())
  return match ? match[1].trim() : null
}

/**
 * Identity extraction middleware.
 *
 * Sole source of truth: the `ory_kratos_session` cookie validated against
 * Kratos `/sessions/whoami`. The previous fallback that trusted unauthenticated
 * `x-user-*` proxy headers was removed — any in-cluster pod could otherwise
 * impersonate an admin by setting those headers.
 *
 * Oathkeeper still mutates `x-user-*` for downstream services and they're
 * forwarded to jinbe, but jinbe ignores them. The session cookie is the
 * only trust anchor.
 *
 * ONE additional trust anchor, off by default (K8S_SA_AUTH_ENABLED): a
 * projected Kubernetes ServiceAccount token, verified by the cluster's API
 * server via TokenReview and mapped to a synthetic subject. It is still not a
 * header we trust — the API server does the verifying — and it grants nothing
 * on its own: the synthetic subject must be a Kratos identity with groups for
 * OPA to resolve any permission.
 */
export async function extractIdentity(
  request: FastifyRequest,
  _reply: FastifyReply,
) {
  // DEV ONLY: bypass auth for local development.
  if (env.NODE_ENV === 'development' && env.DEV_BYPASS_AUTH) {
    const devEmail = env.DEV_USER_EMAIL || 'dev@localhost'
    request.userContext = {
      email: devEmail,
      id: 'dev-user-id',
      name: 'Dev User',
      aal: 'aal2',
      authenticatedAt: new Date(),
      secondFactorAt: new Date(),
      authVia: 'dev',
    }
    request.log.warn(
      { email: devEmail },
      '⚠️  DEV MODE: Authentication bypassed with fake user',
    )
    return
  }

  // MACHINE (M2M): a projected Kubernetes ServiceAccount token. Tried before
  // the cookie because a machine caller has no cookie; a REJECTED bearer token
  // falls through rather than short-circuiting, so a request carrying both a
  // stale token and a valid session still authenticates as the human.
  const bearer = extractBearerToken(request.headers.authorization)
  if (
    bearer &&
    env.K8S_SA_AUTH_ENABLED &&
    k8sTokenReviewService.looksLikeServiceAccountToken(bearer)
  ) {
    const principal = await k8sTokenReviewService.verify(bearer)
    if (principal) {
      request.machine = principal
      request.userContext = {
        email: principal.email,
        // Namespaced so a machine id can never collide with a Kratos uuid.
        id: `k8s:${principal.uid ?? principal.username}`,
        // The real API-server username, so audit records name the actual
        // ServiceAccount and not just its synthetic email.
        name: principal.username,
        authVia: 'machine',
      }
      request.log.debug(
        {
          subject: principal.email,
          serviceAccount: principal.username,
          path: request.url,
        },
        'Machine identity validated via Kubernetes TokenReview',
      )
      return
    }
    request.sessionError = 'k8s_service_account_token_rejected'
    request.log.warn(
      { path: request.url, method: request.method },
      'Bearer ServiceAccount token present but TokenReview rejected it',
    )
  }

  // HUMAN, proven by a signed token. Tried after the ServiceAccount path, whose tokens are also
  // JWTs and are told apart by their subject, and before the cookie, because a caller who sent a
  // token means to be judged on it. A rejected token falls through rather than short-circuiting,
  // matching the ServiceAccount path above: a stale token alongside a valid session should still
  // authenticate as the human.
  if (bearer && oidcBearerService.enabled && oidcBearerService.looksLikeJwt(bearer)) {
    const principal = await oidcBearerService.verify(bearer)
    if (principal) {
      request.userContext = {
        email: principal.email ?? '',
        id: principal.subject,
        name: principal.name ?? 'unknown',
        organisations: principal.organisations,
        authVia: 'bearer',
      }
      request.log.debug(
        {
          subject: principal.subject,
          organisations: principal.organisations.length,
          path: request.url,
        },
        'User identity validated via OIDC bearer token',
      )
      return
    }
    request.sessionError = 'bearer_token_rejected'
  }

  // The session cookie is a method a deployment can decline. Turned off, a caller with a cookie and
  // no token is nobody here — which is the point of turning it off rather than a side effect.
  //
  // Explicitly `=== false`, so a configuration that does not carry the setting at all behaves as
  // this service did before the setting existed. Declining an authentication method is a decision
  // to state, never one to inherit from an absent key.
  if (env.AUTH_COOKIE_ENABLED === false) {
    request.log.debug(
      { path: request.url, method: request.method },
      'Cookie authentication is disabled',
    )
    return
  }

  const cookieHeader = request.headers.cookie
  const sessionCookie = KratosSessionService.extractSessionCookie(cookieHeader)
  if (!sessionCookie) {
    request.log.debug(
      { path: request.url, method: request.method },
      'No ory_kratos_session cookie',
    )
    return
  }

  const { session: validatedSession, error } =
    await kratosSessionService.validateSession(sessionCookie)

  if (validatedSession) {
    request.validatedSession = validatedSession
    request.userContext = {
      email: validatedSession.email,
      id: validatedSession.identityId,
      name: validatedSession.name || 'unknown',
      sessionId: validatedSession.sessionId,
      expiresAt: validatedSession.expiresAt,
      aal: validatedSession.aal,
      authenticatedAt: validatedSession.authenticatedAt,
      secondFactorAt: validatedSession.secondFactorAt,
      authVia: 'session',
    }
    request.log.debug(
      {
        email: validatedSession.email,
        identityId: validatedSession.identityId,
        sessionId: validatedSession.sessionId,
        path: request.url,
      },
      'User identity validated via Kratos session',
    )
    return
  }

  if (error) {
    request.sessionError = error
  }
  request.log.debug(
    { path: request.url, error },
    'Session cookie present but failed validation',
  )
}
