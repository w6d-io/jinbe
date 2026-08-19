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
