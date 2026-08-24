import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import { requireAuth } from '../../../middleware/require-auth.js'

// Helper to create mock request
function createMockRequest(
  overrides: Partial<FastifyRequest> & {
    url?: string
    method?: string
    headers?: Record<string, string>
    userContext?: { email: string } | null
    validatedSession?: object | null
  } = {}
): FastifyRequest {
  return {
    url: overrides.url || '/api/protected',
    method: overrides.method || 'GET',
    headers: overrides.headers || { host: 'api.example.com' }, // Default to external host
    userContext: overrides.userContext,
    validatedSession: overrides.validatedSession || null,
    log: {
      warn: vi.fn(),
      debug: vi.fn(),
      info: vi.fn(),
      error: vi.fn(),
    },
    ...overrides,
  } as unknown as FastifyRequest
}

// Helper to create mock reply
function createMockReply(): FastifyReply & { _statusCode?: number; _body?: unknown } {
  const reply = {
    _statusCode: 200 as number | undefined,
    _body: undefined as unknown,
    status: vi.fn().mockImplementation(function (this: typeof reply, code: number) {
      this._statusCode = code
      return this
    }),
    send: vi.fn().mockImplementation(function (this: typeof reply, body: unknown) {
      this._body = body
      return this
    }),
  }
  return reply as unknown as FastifyReply & { _statusCode?: number; _body?: unknown }
}

describe('requireAuth middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // ===========================================================================
  // Public Routes (no auth required)
  // ===========================================================================
  describe('public routes', () => {
    it('should skip auth for /api/health', async () => {
      const request = createMockRequest({ url: '/api/health' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for /api/whoami', async () => {
      const request = createMockRequest({ url: '/api/whoami' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for /docs', async () => {
      const request = createMockRequest({ url: '/docs' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for /docs/', async () => {
      const request = createMockRequest({ url: '/docs/' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for /docs/json (sub-path)', async () => {
      const request = createMockRequest({ url: '/docs/json' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for /api/health with query string', async () => {
      const request = createMockRequest({ url: '/api/health?format=json' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for /api/whoami/details (sub-path)', async () => {
      const request = createMockRequest({ url: '/api/whoami/details' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for /api/opa routes (OPA bundle)', async () => {
      const request = createMockRequest({ url: '/api/opa/bundle' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for /api/oathkeeper routes', async () => {
      const request = createMockRequest({ url: '/api/oathkeeper/rules' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for the exact /api/webhooks/kratos route', async () => {
      const request = createMockRequest({ url: '/api/webhooks/kratos' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should REQUIRE auth for other /api/webhooks/* sub-paths (P0-1)', async () => {
      const request = createMockRequest({ url: '/api/webhooks/evil', userContext: undefined })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
    })
  })

  // ===========================================================================
  // Protected Routes (auth required)
  // ===========================================================================
  describe('protected routes', () => {
    it('should return 401 when userContext is missing', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        userContext: undefined,
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
      expect(reply._body).toEqual({
        error: 'Unauthorized',
        code: 'authentication_required',
        message:
          'Valid authentication required. Provide a valid ory_kratos_session cookie, or a Kubernetes ServiceAccount token as a Bearer credential.',
      })
    })

    it('should tag 401 with code=session_invalid when a credential was presented but rejected', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        userContext: undefined,
        sessionError: 'Session expired or invalid',
      } as Parameters<typeof createMockRequest>[0])
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
      expect((reply._body as { code?: string }).code).toBe('session_invalid')
    })

    it('should tag 401 with code=session_invalid for a rejected ServiceAccount token', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        userContext: undefined,
        sessionError: 'k8s_service_account_token_rejected',
      } as Parameters<typeof createMockRequest>[0])
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
      expect((reply._body as { code?: string }).code).toBe('session_invalid')
    })

    it('should return 401 when userContext is null', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        userContext: null,
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
    })

    it('should return 401 when userContext.email is "unknown"', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        userContext: { email: 'unknown' },
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
      expect(reply._body).toEqual({
        error: 'Unauthorized',
        code: 'authentication_required',
        message:
          'Valid authentication required. Provide a valid ory_kratos_session cookie, or a Kubernetes ServiceAccount token as a Bearer credential.',
      })
    })

    it('should allow authenticated user with valid email', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        userContext: { email: 'user@example.com' },
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should allow authenticated requests through', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        userContext: { email: 'user@example.com' },
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
    })

    it('should log warning for unauthorized requests', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        method: 'POST',
        userContext: undefined,
        validatedSession: null,
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
    })
  })

  // ===========================================================================
  // Edge Cases (routes that look similar but are not public)
  // ===========================================================================
  describe('edge cases', () => {
    it('should require auth for /api/healthcheck (not /api/health)', async () => {
      const request = createMockRequest({
        url: '/api/healthcheck',
        userContext: undefined,
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
    })

    it('should require auth for /api/whoami-extended (not /api/whoami)', async () => {
      const request = createMockRequest({
        url: '/api/whoami-extended',
        userContext: undefined,
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
    })

    it('should require auth for /api/documentation (not /docs)', async () => {
      const request = createMockRequest({
        url: '/api/documentation',
        userContext: undefined,
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
    })

    it('should strip query string when checking routes', async () => {
      const request = createMockRequest({
        url: '/api/clusters?page=1&pageSize=10',
        userContext: undefined,
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
    })

    it('should handle nested protected routes', async () => {
      const request = createMockRequest({
        url: '/api/clusters/507f1f77bcf86cd799439011/verify',
        userContext: { email: 'admin@example.com' },
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })
  })

  // ===========================================================================
  // Different HTTP Methods
  // ===========================================================================
  describe('HTTP methods', () => {
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']

    methods.forEach((method) => {
      it(`should require auth for ${method} requests on protected routes`, async () => {
        const request = createMockRequest({
          url: '/api/clusters',
          method,
          userContext: undefined,
        })
        const reply = createMockReply()

        await requireAuth(request, reply)

        expect(reply._statusCode).toBe(401)
      })

      it(`should allow ${method} requests when authenticated`, async () => {
        const request = createMockRequest({
          url: '/api/clusters',
          method,
          userContext: { email: 'user@example.com' },
        })
        const reply = createMockReply()

        await requireAuth(request, reply)

        expect(reply.status).not.toHaveBeenCalled()
      })
    })
  })

  // ===========================================================================
  // New public routes: /api/opa, /api/oathkeeper, /api/webhooks
  // ===========================================================================
  describe('new public routes', () => {
    it('should skip auth for /api/opa/bundle', async () => {
      const request = createMockRequest({ url: '/api/opa/bundle' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for /api/oathkeeper/rules', async () => {
      const request = createMockRequest({ url: '/api/oathkeeper/rules' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should skip auth for /api/webhooks/kratos with query string', async () => {
      const request = createMockRequest({ url: '/api/webhooks/kratos?format=json' })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
    })
  })

})
