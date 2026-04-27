import { FastifyRequest, FastifyReply } from 'fastify'
import {
  kratosSessionService,
  KratosSessionService,
  ValidatedSession,
} from '../services/kratos-session.service.js'
import { env } from '../config/index.js'

/**
 * User context extracted from Kratos session or proxy headers
 */
export interface UserContext {
  email: string
  id: string
  name: string
  sessionId?: string
  expiresAt?: Date
  rawHeaders: Record<string, string>
}

/**
 * Extend FastifyRequest to include userContext
 */
declare module 'fastify' {
  interface FastifyRequest {
    userContext?: UserContext
    validatedSession?: ValidatedSession
    sessionError?: string
  }
}

/**
 * Identity extraction middleware
 *
 * Extracts and validates user identity from:
 * 1. ory_kratos_session cookie (validated via Kratos /sessions/whoami)
 * 2. Fallback to proxy headers (X-User-Email, X-User-ID, X-User-Name)
 *
 * The validated session is attached to request.validatedSession
 * The extracted identity is attached to request.userContext
 */
export async function extractIdentity(
  request: FastifyRequest,
  _reply: FastifyReply
) {
  // Store all user-related headers for potential debugging
  const rawHeaders: Record<string, string> = {}
  for (const [key, value] of Object.entries(request.headers)) {
    if (key.toLowerCase().startsWith('x-user-')) {
      rawHeaders[key] = String(value)
    }
  }

  // DEV ONLY: Bypass authentication with fake user
  if (env.NODE_ENV === 'development' && env.DEV_BYPASS_AUTH) {
    const devEmail = env.DEV_USER_EMAIL || 'dev@localhost'
    request.userContext = {
      email: devEmail,
      id: 'dev-user-id',
      name: 'Dev User',
      rawHeaders,
    }
    request.log.warn(
      { email: devEmail },
      '⚠️  DEV MODE: Authentication bypassed with fake user'
    )
    return
  }

  // 1. Try to validate ory_kratos_session cookie
  const cookieHeader = request.headers.cookie
  const sessionCookie = KratosSessionService.extractSessionCookie(cookieHeader)

  if (sessionCookie) {
    const { session: validatedSession, error } =
      await kratosSessionService.validateSession(sessionCookie)

    if (validatedSession) {
      // Session is valid - attach to request
      request.validatedSession = validatedSession
      request.userContext = {
        email: validatedSession.email,
        id: validatedSession.identityId,
        name: validatedSession.name || 'unknown',
        sessionId: validatedSession.sessionId,
        expiresAt: validatedSession.expiresAt,
        rawHeaders,
      }

      request.log.debug(
        {
          email: validatedSession.email,
          identityId: validatedSession.identityId,
          sessionId: validatedSession.sessionId,
          path: request.url,
        },
        'User identity validated via Kratos session'
      )
      return
    }

    // Store the error for routes that need it
    if (error) {
      request.sessionError = error
    }
  }

  // 2. Fallback to proxy headers (AuthKeeper)
  const userEmail = request.headers['x-user-email'] as string | undefined
  const userId = request.headers['x-user-id'] as string | undefined
  const userName = request.headers['x-user-name'] as string | undefined

  if (userEmail || userId) {
    request.userContext = {
      email: userEmail || 'unknown',
      id: userId || 'unknown',
      name: userName || 'unknown',
      rawHeaders,
    }

    request.log.debug(
      {
        userEmail,
        userId,
        userName,
        path: request.url,
      },
      'User identity extracted from proxy headers'
    )
    return
  }

  // No user identity found
  request.log.debug(
    {
      path: request.url,
      method: request.method,
    },
    'No user identity found (no valid session or proxy headers)'
  )
}
