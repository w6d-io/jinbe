import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import { requireAuth, isInternalRequest } from '../../../middleware/require-auth.js'

// Mock OPAL service for requireAdmin tests
const { mockGetUserInfo } = vi.hoisted(() => ({
  mockGetUserInfo: vi.fn(),
}))
vi.mock('../../../services/opa.service.js', () => ({
  opaService: { getUserInfo: mockGetUserInfo },
  opalService: { getUserInfo: mockGetUserInfo },
}))

import { requireAdmin } from '../../../middleware/require-admin.js'

// Helper to create mock request
function createMockRequest(
  overrides: Partial<FastifyRequest> & {
    url?: string
    method?: string
    headers?: Record<string, string>
    userContext?: { email: string } | null
    validatedSession?: object | null
    rbacInfo?: object | null
  } = {}
): FastifyRequest {
  return {
    url: overrides.url || '/api/protected',
    method: overrides.method || 'GET',
    headers: overrides.headers || {},
    userContext: overrides.userContext,
    validatedSession: overrides.validatedSession || null,
    rbacInfo: overrides.rbacInfo || null,
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

describe('internal cluster detection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // ===========================================================================
  // isInternalRequest helper function
  // ===========================================================================
  describe('isInternalRequest', () => {
    it('should return true for Host containing w6d-ops', () => {
      const request = createMockRequest({
        headers: { host: 'jinbe.w6d-ops:8080' },
      })

      expect(isInternalRequest(request)).toBe(true)
    })

    it('should return false for Host with w6d-ops as substring (security: no substring match)', () => {
      const request = createMockRequest({
        headers: { host: 'api.w6d-ops.local:8080' },
      })

      expect(isInternalRequest(request)).toBe(false)
    })

    it('should return false for external Host', () => {
      const request = createMockRequest({
        headers: { host: 'jinbe.example.com' },
      })

      expect(isInternalRequest(request)).toBe(false)
    })

    it('should return false for localhost without w6d-ops', () => {
      const request = createMockRequest({
        headers: { host: 'localhost:8080' },
      })

      expect(isInternalRequest(request)).toBe(false)
    })

    it('should return false when Host header is missing', () => {
      const request = createMockRequest({
        headers: {},
      })

      expect(isInternalRequest(request)).toBe(false)
    })
  })

  // ===========================================================================
  // requireAuth — no internal bypass (removed as security risk)
  // ===========================================================================
  describe('requireAuth', () => {
    it('should require auth for internal Host (bypass removed)', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        headers: { host: 'jinbe.w6d-ops:8080' },
        userContext: undefined,
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
    })

    it('should require auth for external Host on protected routes', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        headers: { host: 'jinbe.example.com' },
        userContext: undefined,
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply._statusCode).toBe(401)
    })

    it('should allow authenticated requests', async () => {
      const request = createMockRequest({
        url: '/api/clusters',
        headers: { host: 'jinbe.example.com' },
        userContext: { email: 'user@example.com' },
      })
      const reply = createMockReply()

      await requireAuth(request, reply)

      expect(reply.status).not.toHaveBeenCalled()
    })
  })

  // ===========================================================================
  // requireAdmin — all requests require real auth
  // ===========================================================================
  describe('requireAdmin', () => {
    it('should require admin check for all requests (no internal bypass)', async () => {
      // Mock OPAL to return non-admin user
      mockGetUserInfo.mockResolvedValueOnce({
        email: 'user@example.com',
        groups: ['users'],
        roles: [],
        permissions: [],
      })

      const request = createMockRequest({
        url: '/api/admin/rbac/users',
        headers: { host: 'jinbe.example.com' },
        userContext: { email: 'user@example.com' },
      })
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply._statusCode).toBe(403) // Forbidden
    })

    it('should allow external admin requests with proper groups', async () => {
      // Mock OPAL to return admin user
      mockGetUserInfo.mockResolvedValueOnce({
        email: 'admin@example.com',
        groups: ['admin'],
        roles: ['admin'],
        permissions: ['*'],
      })

      const request = createMockRequest({
        url: '/api/admin/rbac/users',
        headers: { host: 'jinbe.example.com' },
        userContext: { email: 'admin@example.com' },
      })
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply.status).not.toHaveBeenCalled() // No error
    })
  })
})
