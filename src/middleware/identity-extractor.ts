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
import { delegatedTokenService } from '../services/delegated-token.service.js'

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
  authVia?: 'session' | 'bearer' | 'machine' | 'dev' | 'delegated'
  /**
   * Set only with authVia 'delegated': the client acting for this user and the scopes the token
   * narrows them to (middleware/delegation-gate.ts). Bound to no organization.
   */
  delegation?: Delegation
  /**
   * The organisations the caller's token asserts, when the deployment reads them from the token
   * rather than from this service's own model. Empty in `local` mode, where the model answers —
   * never a merge of the two, because two authorities on one question cannot be told apart when
   * they disagree.
   */
  organisations?: readonly string[]
}

/** A user acting through a client (an MCP server, a personal key). Audit records it as `act`. */
export interface Delegation {
  clientId: string
  scopes: readonly string[]
  /** An OAuth token's consent org, when it names one — informational, never an authorization. */
  org?: string
  kind: 'oauth' | 'personal'
  /** The in-cluster service that presented the token (its ServiceAccount name, e.g. auth-mcp). */
  via: string
  /** Personal key: when its creator proved a second factor, and whether the key may use that proof. */
  keyStepUpAt?: string
  keyStepUpActions?: boolean
  /** Browser sign-in: the consent-time second factor, whether protected actions were allowed, and until when. */
  stepUpAt?: string
  stepUpActions?: boolean
  stepUpUntil?: string
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
 * The in-cluster service presenting a delegated token: its projected ServiceAccount token in
 * X-Actor-Token, verified by TokenReview and listed in DELEGATED_ACTOR_SUBJECTS. Returns the
 * ServiceAccount name, or null.
 */
export async function verifiedActor(request: FastifyRequest): Promise<string | null> {
  const header = request.headers['x-actor-token']
  const token = Array.isArray(header) ? undefined : header?.trim()
  if (!token || !k8sTokenReviewService.looksLikeServiceAccountToken(token)) return null
  const principal = await k8sTokenReviewService.verify(token)
  if (!principal) return null
  const allowed = env.DELEGATED_ACTOR_SUBJECTS
  return allowed.includes(`${principal.namespace}:${principal.serviceAccount}`) ? principal.serviceAccount : null
}

/** A request that cannot change anything: the only kind a cached session validation may serve. */
function isRead(request: FastifyRequest): boolean {
  return request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS'
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

/**
 * The second-factor evidence carried by the Kratos session accompanying a token, when it names the
 * same subject. Null when there is no session, it does not validate, or it belongs to somebody
 * else — in which case the caller is judged on the token alone and the gate refuses under
 * `step_up_unavailable`, which says so rather than asking for a factor nothing reads.
 */
async function secondFactorFromSession(request: FastifyRequest, subject: string) {
  const cookie = KratosSessionService.extractSessionCookie(request.headers.cookie)
  if (!cookie) return null
  const { session } = await kratosSessionService.validateSession(cookie, { allowCached: isRead(request) })
  if (!session || session.identityId !== subject) return null
  return {
    sessionId: session.sessionId,
    aal: session.aal,
    authenticatedAt: session.authenticatedAt,
    secondFactorAt: session.secondFactorAt,
    authVia: 'session' as const,
  }
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

  // A USER THROUGH A CLIENT (off by default, DELEGATED_TOKENS_ENABLED): an opaque Hydra token, only
  // together with the presenting service's own ServiceAccount token in X-Actor-Token. The token alone
  // is refused — stolen from the client, it cannot be replayed here — and so is the actor alone.
  // Not on /api/mcp/*: there the token is the SUBJECT of the request (token-info, key exchange), not
  // the caller's credential — the actor is the caller, checked by that plugin's own hook.
  if (
    bearer &&
    delegatedTokenService.enabled &&
    delegatedTokenService.looksOpaque(bearer) &&
    !(request.url || '').startsWith('/api/mcp/')
  ) {
    const actor = await verifiedActor(request)
    const result = actor ? await delegatedTokenService.resolve(bearer) : { error: 'actor_missing' }
    if (actor && 'principal' in result) {
      const p = result.principal
      request.userContext = {
        email: p.email,
        id: p.subject,
        name: p.name,
        authVia: 'delegated',
        delegation: { clientId: p.clientId, scopes: p.scopes, kind: p.kind, via: actor, ...(p.org ? { org: p.org } : {}), ...(p.keyStepUpAt ? { keyStepUpAt: p.keyStepUpAt } : {}), ...(p.keyStepUpActions !== undefined ? { keyStepUpActions: p.keyStepUpActions } : {}), ...(p.kind === 'oauth' ? { stepUpActions: p.stepUpActions === true, ...(p.stepUpAt ? { stepUpAt: p.stepUpAt } : {}), ...(p.stepUpUntil ? { stepUpUntil: p.stepUpUntil } : {}) } : {}) },
      }
      request.log.debug(
        { subject: p.subject, clientId: p.clientId, org: p.org, kind: p.kind, via: actor, path: request.url },
        'User identity validated via delegated token',
      )
      return
    }
    request.sessionError = 'delegated_token_rejected'
    request.log.warn(
      { path: request.url, method: request.method, reason: 'error' in result ? result.error : 'unknown' },
      'Delegated token presented but refused',
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
      // A token asserts WHO, never how recently they proved a second factor — no such claim is
      // issued. A step-up gate reading only the token therefore refuses forever: the operator
      // proves a factor, comes back, and the token still says nothing. It is a loop with no exit.
      //
      // Same browser, same origin: the Kratos session travels alongside the token. When it is
      // present AND belongs to the SAME subject, the factor evidence is taken from it. The token
      // stays the authority on identity — this joins one dimension the token cannot express, and
      // only for a subject the token already named, so it can never widen who the caller is.
      const factor = await secondFactorFromSession(request, principal.subject)
      request.userContext = {
        email: principal.email ?? '',
        id: principal.subject,
        name: principal.name ?? 'unknown',
        organisations: principal.organisations,
        ...(factor ?? { authVia: 'bearer' as const }),
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

  // Reads may reuse a validation made in the last few seconds; writes always ask Kratos (see the
  // session cache in kratos-session.service).
  const { session: validatedSession, error } =
    await kratosSessionService.validateSession(sessionCookie, { allowCached: isRead(request) })

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
