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

// What the caller holds comes from the model the engine decides against, keyed on the immutable
// identity. It used to be resolved from Kratos metadata through a cache, so what let somebody into
// the console was decided by something nobody enforces.
vi.mock('../../../services/authorization-model.service.js', () => ({
  platformRightsOf: vi.fn().mockImplementation(async () => {
    const held = mockState.opalUserInfo
    if (!held) throw new Error('the model could not be read')
    return { groups: held.groups, roles: held.roles, permissions: held.permissions }
  }),
  AuthorizationModelUnavailableError: class extends Error {},
}))

import { requireAdmin, requireGroups } from '../../../middleware/require-admin.js'
import { platformRightsOf } from '../../../services/authorization-model.service.js'

/** The reader the guard consults. Named as before so the assertions read the same. */
const opalService = { getUserInfo: platformRightsOf }

// Helper to create mock request
function createMockRequest(email?: string, rbacInfo?: UserRbacInfo): FastifyRequest {
  return {
    // The gate keys on the identity; the address is for the log and the trail.
    userContext: email ? { email, ...(email === 'unknown' ? {} : { id: `subject-of-${email}` }) } : undefined,
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
      // What the bypass stamps must PASS the gate it skips: a permission, not a group name.
      expect(request.rbacInfo?.permissions).toContain('admin:read')
      expect(request.rbacInfo?.permissions).toContain('admin:write')
    })

    it('should set rbacInfo with superadmin and admin groups', async () => {
      mockState.env.DEV_BYPASS_AUTH = true
      mockState.env.NODE_ENV = 'development'

      const request = createMockRequest('dev@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(request.rbacInfo).toEqual({
        email: 'dev@example.com',
        groups: ['platform-admin'],
        roles: ['platform-admin'],
        permissions: ['admin:read', 'admin:write'],
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
    it('should return 503 when what the caller holds cannot be resolved', async () => {
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
    it('grants access when the caller holds the permission exactly', async () => {
      mockState.opalUserInfo = {
        email: 'admin@example.com',
        groups: ['platform-auditor'],
        roles: ['admin'],
        permissions: ['admin:read'],
      }

      const request = createMockRequest('admin@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply.send).not.toHaveBeenCalled()
      expect(request.rbacInfo).toBeDefined()
    })

    it('grants access when the caller holds an ancestor of it', async () => {
      mockState.opalUserInfo = {
        email: 'superadmin@example.com',
        groups: ['platform-admin'],
        roles: ['superadmin'],
        permissions: ['admin:read', 'admin:write'],
      }

      const request = createMockRequest('superadmin@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply.send).not.toHaveBeenCalled()
    })

    it('refuses a group named like an admin group that grants nothing', async () => {
      // The check this replaces matched group NAMES, case-insensitively — so a group called `Admin`
      // waved somebody through whatever it granted. Reading the administration API needs
      // `admin:read`, and a name is not a permission.
      mockState.opalUserInfo = {
        email: 'user@example.com',
        groups: ['Admin'],
        roles: [],
        permissions: [],
      }

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await requireAdmin(request, reply)

      expect(reply._statusCode).toBe(403)
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

  it('should resolve what the caller holds when it is not already known', async () => {
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

    // The IDENTITY, and only it: an address can be changed by its owner and reused by somebody else.
    expect(opalService.getUserInfo).toHaveBeenCalledWith('subject-of-user@example.com')
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
