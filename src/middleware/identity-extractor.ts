import { FastifyRequest, FastifyReply } from 'fastify'
import {
  kratosSessionService,
  KratosSessionService,
  ValidatedSession,
} from '../services/kratos-session.service.js'
import { env } from '../config/index.js'

/**
 * User context derived from the validated Kratos session.
 */
export interface UserContext {
  email: string
  id: string
  name: string
  sessionId?: string
  expiresAt?: Date
}

declare module 'fastify' {
  interface FastifyRequest {
    userContext?: UserContext
    validatedSession?: ValidatedSession
    sessionError?: string
  }
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
    }
    request.log.warn(
      { email: devEmail },
      '⚠️  DEV MODE: Authentication bypassed with fake user',
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
