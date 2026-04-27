import { env } from '../config/index.js'

/**
 * Kratos Session Identity (from toSession response)
 */
export interface KratosSessionIdentity {
  id: string
  schema_id: string
  traits: {
    email: string
    name?: string
    picture?: string
    providers?: Array<{
      name: string
      issuer_url: string
      provider_type: string
    }>
  }
  state: string
  created_at: string
  updated_at: string
}

/**
 * Kratos Session response from /sessions/whoami
 */
export interface KratosSession {
  id: string
  active: boolean
  expires_at: string
  authenticated_at: string
  authenticator_assurance_level: string
  identity: KratosSessionIdentity
}

/**
 * Validated session result
 */
export interface ValidatedSession {
  sessionId: string
  email: string
  identityId: string
  name?: string
  picture?: string
  expiresAt: Date
  active: boolean
}

/**
 * Session validation result with error info
 */
export interface SessionValidationResult {
  session: ValidatedSession | null
  error?: string
}

/**
 * Kratos Public API Service
 * Handles session validation via Ory Kratos Public API
 */
export class KratosSessionService {
  private publicUrl: string

  constructor() {
    this.publicUrl = env.KRATOS_PUBLIC_URL
  }

  /**
   * Validate session by calling Kratos /sessions/whoami
   * This endpoint validates the ory_kratos_session cookie
   *
   * @param sessionCookie - The ory_kratos_session cookie value
   * @returns SessionValidationResult with session if valid, or error message if invalid
   */
  async validateSession(sessionCookie: string): Promise<SessionValidationResult> {
    try {
      const url = `${this.publicUrl}/sessions/whoami`

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          Cookie: `ory_kratos_session=${sessionCookie}`,
        },
      })

      if (!response.ok) {
        // 401 = session invalid/expired, 403 = no session
        if (response.status === 401) {
          return { session: null, error: 'Session expired or invalid' }
        }
        if (response.status === 403) {
          return { session: null, error: 'No active session' }
        }
        return { session: null, error: `Kratos error: ${response.status} ${response.statusText}` }
      }

      const session: KratosSession = await response.json()

      // Check if session is active
      if (!session.active) {
        return { session: null, error: 'Session is not active' }
      }

      // Check if session is expired
      const expiresAt = new Date(session.expires_at)
      if (expiresAt < new Date()) {
        return { session: null, error: 'Session has expired' }
      }

      return {
        session: {
          sessionId: session.id,
          email: session.identity.traits.email,
          identityId: session.identity.id,
          name: session.identity.traits.name || undefined,
          picture: session.identity.traits.picture || undefined,
          expiresAt,
          active: session.active,
        },
      }
    } catch (error) {
      console.error('Kratos session validation error:', error)
      return { session: null, error: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}` }
    }
  }

  /**
   * Extract ory_kratos_session cookie from cookie header
   */
  static extractSessionCookie(cookieHeader: string | undefined): string | null {
    if (!cookieHeader) return null

    const cookies = cookieHeader.split(';').map((c) => c.trim())
    for (const cookie of cookies) {
      const [name, ...valueParts] = cookie.split('=')
      if (name === 'ory_kratos_session') {
        return valueParts.join('=') // Handle '=' in cookie value
      }
    }
    return null
  }
}

export const kratosSessionService = new KratosSessionService()
