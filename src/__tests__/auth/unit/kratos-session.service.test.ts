import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createKratosSession } from '../fixtures/kratos.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  env: {
    KRATOS_PUBLIC_URL: 'http://kratos-public:4433',
  },
}))

// Mock env configuration
vi.mock('../../../config/index.js', () => ({
  env: mockState.env,
}))

// Helper to create mock fetch response
function createMockResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : status === 401 ? 'Unauthorized' : 'Error',
    json: async () => body,
  }
}

// Import after mocking
import { KratosSessionService } from '../../../services/kratos-session.service.js'

describe('KratosSessionService', () => {
  let service: KratosSessionService
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.clearAllMocks()

    // Reset mock state
    mockState.env.KRATOS_PUBLIC_URL = 'http://kratos-public:4433'

    // Create mock fetch
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)

    // Create fresh service instance
    service = new KratosSessionService()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('validateSession', () => {
    it('should return valid session for active session', async () => {
      const session = createKratosSession('user@example.com', {
        sessionId: 'session-123',
        identityId: 'identity-456',
        name: 'Test User',
        picture: 'https://example.com/avatar.png',
      })
      mockFetch.mockResolvedValueOnce(createMockResponse(200, session))

      const result = await service.validateSession('valid-session-cookie')

      expect(result.session).not.toBeNull()
      expect(result.session?.email).toBe('user@example.com')
      expect(result.session?.sessionId).toBe('session-123')
      expect(result.session?.identityId).toBe('identity-456')
      expect(result.session?.name).toBe('Test User')
      expect(result.session?.picture).toBe('https://example.com/avatar.png')
      expect(result.session?.active).toBe(true)
      expect(result.error).toBeUndefined()
    })

    it('should return error for 401 unauthorized', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(401, {}))

      const result = await service.validateSession('expired-cookie')

      expect(result.session).toBeNull()
      expect(result.error).toBe('Session expired or invalid')
    })

    it('should return error for 403 forbidden', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(403, {}))

      const result = await service.validateSession('no-session-cookie')

      expect(result.session).toBeNull()
      expect(result.error).toBe('No active session')
    })

    it('should return error for other HTTP errors', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(500, {}))

      const result = await service.validateSession('cookie')

      expect(result.session).toBeNull()
      expect(result.error).toContain('Kratos error: 500')
    })

    it('should return error for inactive session', async () => {
      const session = createKratosSession('user@example.com', { active: false })
      mockFetch.mockResolvedValueOnce(createMockResponse(200, session))

      const result = await service.validateSession('inactive-session')

      expect(result.session).toBeNull()
      expect(result.error).toBe('Session is not active')
    })

    it('should return error for expired session', async () => {
      const expiredSession = createKratosSession('user@example.com', {
        expiresAt: new Date(Date.now() - 1000), // Expired 1 second ago
      })
      mockFetch.mockResolvedValueOnce(createMockResponse(200, expiredSession))

      const result = await service.validateSession('expired-session')

      expect(result.session).toBeNull()
      expect(result.error).toBe('Session has expired')
    })

    it('should send correct cookie header', async () => {
      const session = createKratosSession('user@example.com')
      mockFetch.mockResolvedValueOnce(createMockResponse(200, session))

      await service.validateSession('my-session-cookie-value')

      expect(mockFetch).toHaveBeenCalledWith(
        'http://kratos-public:4433/sessions/whoami',
        expect.objectContaining({
          method: 'GET',
          headers: {
            Cookie: 'ory_kratos_session=my-session-cookie-value',
          },
        })
      )
    })

    it('should handle fetch errors gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'))

      const result = await service.validateSession('cookie')

      expect(result.session).toBeNull()
      expect(result.error).toContain('Validation error: Network error')
    })

    it('should handle non-Error thrown objects', async () => {
      mockFetch.mockRejectedValueOnce('String error')

      const result = await service.validateSession('cookie')

      expect(result.session).toBeNull()
      expect(result.error).toContain('Unknown error')
    })

    it('should return session without optional fields', async () => {
      const session = createKratosSession('user@example.com', {
        name: undefined,
        picture: undefined,
      })
      mockFetch.mockResolvedValueOnce(createMockResponse(200, session))

      const result = await service.validateSession('cookie')

      expect(result.session).not.toBeNull()
      expect(result.session?.name).toBeUndefined()
      expect(result.session?.picture).toBeUndefined()
    })
  })

  describe('extractSessionCookie', () => {
    it('should extract ory_kratos_session cookie', () => {
      const cookieHeader = 'other=value; ory_kratos_session=session123; another=test'

      const result = KratosSessionService.extractSessionCookie(cookieHeader)

      expect(result).toBe('session123')
    })

    it('should return null when cookie header is undefined', () => {
      const result = KratosSessionService.extractSessionCookie(undefined)

      expect(result).toBeNull()
    })

    it('should return null when ory_kratos_session cookie is not present', () => {
      const cookieHeader = 'other=value; another=test'

      const result = KratosSessionService.extractSessionCookie(cookieHeader)

      expect(result).toBeNull()
    })

    it('should handle cookie value with equals sign', () => {
      const cookieHeader = 'ory_kratos_session=abc=def=ghi'

      const result = KratosSessionService.extractSessionCookie(cookieHeader)

      expect(result).toBe('abc=def=ghi')
    })

    it('should handle single cookie', () => {
      const cookieHeader = 'ory_kratos_session=mysession'

      const result = KratosSessionService.extractSessionCookie(cookieHeader)

      expect(result).toBe('mysession')
    })

    it('should handle cookies with whitespace', () => {
      const cookieHeader = '  ory_kratos_session=session123  ;  other=value  '

      const result = KratosSessionService.extractSessionCookie(cookieHeader)

      expect(result).toBe('session123')
    })
  })
})
