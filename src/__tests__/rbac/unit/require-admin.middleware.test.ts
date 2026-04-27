import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import type { UserRbacInfo } from '../../../services/opa.service.js'

// Use vi.hoisted to ensure mockState is available when vi.mock is hoisted
const mockState = vi.hoisted(() => ({
  env: {
    DEV_BYPASS_AUTH: false as boolean,
    NODE_ENV: 'test' as string,
    APP_NAME: 'jinbe',
  },
  opalUserInfo: null as UserRbacInfo | null,
}))

vi.mock('../../../config/env.js', () => ({
  env: mockState.env,
}))

vi.mock('../../../services/opa.service.js', () => ({
  opaService: { getUserInfo: vi.fn().mockImplementation(async () => mockState.opalUserInfo) },
  opalService: { getUserInfo: vi.fn().mockImplementation(async () => mockState.opalUserInfo) },
}))

import { requireAdmin, requireGroups } from '../../../middleware/require-admin.js'
import { opaService as opalService } from '../../../services/opa.service.js'

// Helper to create mock request
function createMockRequest(email?: string, rbacInfo?: UserRbacInfo): FastifyRequest {
  return {
    userContext: email ? { email } : undefined,
    rbacInfo,
    headers: { host: 'api.example.com' }, // Default to external host
    log: {
      warn: vi.fn(),
      debug: vi.fn(),
    },
  } as unknown as FastifyRequest
}

// Helper to create mock reply
function createMockReply(): FastifyReply & { _statusCode?: number; _body?: unknown } {
  const reply = {
    _statusCode: undefined as number | undefined,
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

describe('requireAdmin middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset mock state
    mockState.env.DEV_BYPASS_AUTH = false
    mockState.env.NODE_ENV = 'test'
    mockState.opalUserInfo = null
  })

  describe('DEV_BYPASS_AUTH mode (hardcoded admin)', () => {
    it('should bypass OPAL and grant admin when DEV_BYPASS_AUTH=true AND NODE_ENV=development', async () => {
      mockState.env.DEV_BYPASS_AUTH = true
      mockState.env.NODE_ENV = 'development'

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      // Should not call OPAL
      expect(opalService.getUserInfo).not.toHaveBeenCalled()
      // Should not send error response
      expect(reply.send).not.toHaveBeenCalled()
      // Should set rbacInfo with admin groups
      expect(request.rbacInfo).toBeDefined()
      expect(request.rbacInfo?.groups).toContain('super_admins')
      expect(request.rbacInfo?.groups).toContain('admins')
    })

    it('should set rbacInfo with superadmin and admin groups', async () => {
      mockState.env.DEV_BYPASS_AUTH = true
      mockState.env.NODE_ENV = 'development'

      const request = createMockRequest('dev@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(request.rbacInfo).toEqual({
        email: 'dev@example.com',
        groups: ['super_admins', 'admins'],
        roles: ['super_admin', 'admin'],
        permissions: ['*'],
      })
    })

    it('should NOT bypass when NODE_ENV=production even if DEV_BYPASS_AUTH=true', async () => {
      mockState.env.DEV_BYPASS_AUTH = true
      mockState.env.NODE_ENV = 'production'
      mockState.opalUserInfo = null

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      // Should call OPAL
      expect(opalService.getUserInfo).toHaveBeenCalled()
      // Should return 503 since OPAL returns null
      expect(reply._statusCode).toBe(503)
    })

    it('should NOT bypass when DEV_BYPASS_AUTH=false', async () => {
      mockState.env.DEV_BYPASS_AUTH = false
      mockState.env.NODE_ENV = 'development'
      mockState.opalUserInfo = null

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(opalService.getUserInfo).toHaveBeenCalled()
    })
  })

  describe('no user context', () => {
    it('should return 401 when email is missing', async () => {
      const request = createMockRequest(undefined)
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply._statusCode).toBe(401)
      expect(reply._body).toEqual({
        error: 'Unauthorized',
        message: 'Authentication required',
      })
    })

    it('should return 401 when email is "unknown"', async () => {
      const request = createMockRequest('unknown')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply._statusCode).toBe(401)
    })
  })

  describe('OPAL unavailable', () => {
    it('should return 503 when opalService.getUserInfo returns null', async () => {
      mockState.opalUserInfo = null

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply._statusCode).toBe(503)
      expect(reply._body).toEqual({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    })
  })

  describe('authorization checks', () => {
    it('should grant access when user in admin group', async () => {
      mockState.opalUserInfo = {
        email: 'admin@example.com',
        groups: ['admin'],
        roles: ['admin'],
        permissions: ['*'],
      }

      const request = createMockRequest('admin@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply.send).not.toHaveBeenCalled()
      expect(request.rbacInfo).toBeDefined()
    })

    it('should grant access when user in superadmin group', async () => {
      mockState.opalUserInfo = {
        email: 'superadmin@example.com',
        groups: ['superadmin'],
        roles: ['superadmin'],
        permissions: ['*'],
      }

      const request = createMockRequest('superadmin@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should grant access with case-insensitive group matching', async () => {
      mockState.opalUserInfo = {
        email: 'user@example.com',
        groups: ['Admin'], // Capital A
        roles: [],
        permissions: [],
      }

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply.send).not.toHaveBeenCalled()
    })

    it('should return 403 when user not in admin groups', async () => {
      mockState.opalUserInfo = {
        email: 'user@example.com',
        groups: ['devs', 'viewers'],
        roles: ['developer'],
        permissions: ['read'],
      }

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply._statusCode).toBe(403)
      expect(reply._body).toEqual({
        error: 'Forbidden',
        message: 'Admin or superadmin access required',
      })
    })

    it('should attach rbacInfo to request on success', async () => {
      mockState.opalUserInfo = {
        email: 'admin@example.com',
        groups: ['admin', 'devs'],
        roles: ['admin', 'developer'],
        permissions: ['read', 'write', 'admin'],
      }

      const request = createMockRequest('admin@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(request.rbacInfo).toEqual(mockState.opalUserInfo)
    })
  })
})

describe('requireGroups factory function', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockState.env.DEV_BYPASS_AUTH = false
    mockState.env.NODE_ENV = 'test'
    mockState.opalUserInfo = null
  })

  it('should create middleware that checks for specified groups', async () => {
    const middleware = requireGroups(['developers', 'testers'])
    expect(typeof middleware).toBe('function')
  })

  it('should grant access when user in any allowed group', async () => {
    mockState.opalUserInfo = {
      email: 'dev@example.com',
      groups: ['developers'],
      roles: [],
      permissions: [],
    }

    const middleware = requireGroups(['developers', 'testers'])
    const request = createMockRequest('dev@example.com')
    const reply = createMockReply()

    await middleware(request, reply)

    expect(reply.send).not.toHaveBeenCalled()
  })

  it('should return 403 when user not in any allowed group', async () => {
    mockState.opalUserInfo = {
      email: 'user@example.com',
      groups: ['viewers'],
      roles: [],
      permissions: [],
    }

    const middleware = requireGroups(['developers', 'testers'])
    const request = createMockRequest('user@example.com')
    const reply = createMockReply()

    await middleware(request, reply)

    expect(reply._statusCode).toBe(403)
    expect(reply._body).toEqual({
      error: 'Forbidden',
      message: 'Access requires membership in one of: developers, testers',
    })
  })

  it('should reuse existing request.rbacInfo if already fetched', async () => {
    const existingRbacInfo: UserRbacInfo = {
      email: 'user@example.com',
      groups: ['developers'],
      roles: [],
      permissions: [],
    }

    const middleware = requireGroups(['developers'])
    const request = createMockRequest('user@example.com', existingRbacInfo)
    const reply = createMockReply()

    await middleware(request, reply)

    // Should NOT call OPAL since rbacInfo already exists
    expect(opalService.getUserInfo).not.toHaveBeenCalled()
    expect(reply.send).not.toHaveBeenCalled()
  })

  it('should fetch rbacInfo from OPAL if not present', async () => {
    mockState.opalUserInfo = {
      email: 'user@example.com',
      groups: ['developers'],
      roles: [],
      permissions: [],
    }

    const middleware = requireGroups(['developers'])
    const request = createMockRequest('user@example.com')
    const reply = createMockReply()

    await middleware(request, reply)

    expect(opalService.getUserInfo).toHaveBeenCalledWith('user@example.com', 'jinbe')
  })

  it('should return 503 when OPAL unavailable', async () => {
    mockState.opalUserInfo = null

    const middleware = requireGroups(['developers'])
    const request = createMockRequest('user@example.com')
    const reply = createMockReply()

    await middleware(request, reply)

    expect(reply._statusCode).toBe(503)
  })

  it('should return 401 when email is missing', async () => {
    const middleware = requireGroups(['developers'])
    const request = createMockRequest(undefined)
    const reply = createMockReply()

    await middleware(request, reply)

    expect(reply._statusCode).toBe(401)
  })
})
