import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import type { UserRbacInfo } from '../../../services/opa.service.js'

const mockState = vi.hoisted(() => ({
  env: {
    DEV_BYPASS_AUTH: false as boolean,
    NODE_ENV: 'test' as string,
    APP_NAME: 'jinbe',
  },
  opaUserInfo: null as UserRbacInfo | null,
}))

vi.mock('../../../config/env.js', () => ({
  env: mockState.env,
}))

vi.mock('../../../config/index.js', () => ({
  env: mockState.env,
}))

vi.mock('../../../services/opa.service.js', () => ({
  opaService: {
    getUserInfo: vi.fn().mockImplementation(async () => mockState.opaUserInfo),
  },
}))

vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: {
    emit: vi.fn().mockResolvedValue(undefined),
  },
}))

import {
  requireServiceAdmin,
  requireServicePermission,
} from '../../../middleware/require-service-admin.js'
import { opaService } from '../../../services/opa.service.js'

function createMockRequest(
  email?: string,
  params?: Record<string, string>,
  rbacInfo?: UserRbacInfo
): FastifyRequest {
  return {
    userContext: email ? { email } : undefined,
    rbacInfo,
    method: 'GET',
    url: '/api/organizations/org-1/users/u-1/groups',
    ip: '127.0.0.1',
    headers: { 'user-agent': 'test' },
    params: params ?? {},
    log: {
      warn: vi.fn(),
      debug: vi.fn(),
      info: vi.fn(),
    },
  } as unknown as FastifyRequest
}

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

describe('requireServiceAdmin middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockState.env.DEV_BYPASS_AUTH = false
    mockState.env.NODE_ENV = 'test'
    mockState.opaUserInfo = null
  })

  describe('DEV_BYPASS_AUTH mode', () => {
    it('bypasses OPA and grants wildcard permissions when DEV_BYPASS_AUTH=true AND NODE_ENV=development', async () => {
      mockState.env.DEV_BYPASS_AUTH = true
      mockState.env.NODE_ENV = 'development'

      const request = createMockRequest('dev@example.com', { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(opaService.getUserInfo).not.toHaveBeenCalled()
      expect(reply.send).not.toHaveBeenCalled()
      expect(request.rbacInfo).toEqual({
        email: 'dev@example.com',
        groups: ['super_admins', 'admins'],
        roles: ['super_admin', 'admin'],
        permissions: ['*'],
      })
    })

    it('does not bypass when NODE_ENV=production', async () => {
      mockState.env.DEV_BYPASS_AUTH = true
      mockState.env.NODE_ENV = 'production'

      const request = createMockRequest('dev@example.com', { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(opaService.getUserInfo).toHaveBeenCalled()
    })
  })

  describe('no user context', () => {
    it('returns 401 when email is missing', async () => {
      const request = createMockRequest(undefined, { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(reply._statusCode).toBe(401)
      expect(reply._body).toEqual({
        error: 'Unauthorized',
        message: 'Authentication required',
      })
    })

    it('returns 401 when email is "unknown"', async () => {
      const request = createMockRequest('unknown', { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(reply._statusCode).toBe(401)
    })
  })

  describe('OPA query', () => {
    it('queries OPA with the param value as the app', async () => {
      mockState.opaUserInfo = {
        email: 'user@example.com',
        groups: ['admins'],
        roles: ['admin'],
        permissions: ['rbac:read'],
      }

      const request = createMockRequest('user@example.com', { organizationId: 'org-42' })
      const reply = createMockReply()

      await requireServiceAdmin('organizationId')(request, reply)

      expect(opaService.getUserInfo).toHaveBeenCalledWith('user@example.com', 'org-42')
    })

    it('respects custom paramName', async () => {
      mockState.opaUserInfo = {
        email: 'user@example.com',
        groups: ['admins'],
        roles: ['admin'],
        permissions: ['rbac:read'],
      }

      const request = createMockRequest('user@example.com', { customId: 'svc-7' })
      const reply = createMockReply()

      await requireServiceAdmin('customId')(request, reply)

      expect(opaService.getUserInfo).toHaveBeenCalledWith('user@example.com', 'svc-7')
    })

    it('returns 503 when OPA returns null', async () => {
      mockState.opaUserInfo = null

      const request = createMockRequest('user@example.com', { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(reply._statusCode).toBe(503)
      expect(reply._body).toEqual({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    })
  })

  describe('authorization checks', () => {
    it('grants access and attaches rbacInfo when user has at least one permission', async () => {
      mockState.opaUserInfo = {
        email: 'user@example.com',
        groups: ['admins'],
        roles: ['admin'],
        permissions: ['rbac:read'],
      }

      const request = createMockRequest('user@example.com', { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(reply.send).not.toHaveBeenCalled()
      expect(request.rbacInfo).toEqual(mockState.opaUserInfo)
    })

    it('returns 403 when permissions are empty', async () => {
      mockState.opaUserInfo = {
        email: 'user@example.com',
        groups: [],
        roles: [],
        permissions: [],
      }

      const request = createMockRequest('user@example.com', { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(reply._statusCode).toBe(403)
      expect(reply._body).toMatchObject({ error: 'Forbidden' })
    })
  })
})

describe('requireServicePermission factory', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockState.env.DEV_BYPASS_AUTH = false
    mockState.env.NODE_ENV = 'test'
    mockState.opaUserInfo = null
  })

  it('returns a middleware function', () => {
    const mw = requireServicePermission('rbac:write')
    expect(typeof mw).toBe('function')
  })

  it('returns 500 when rbacInfo is missing (requireServiceAdmin not run first)', async () => {
    const mw = requireServicePermission('rbac:write')
    const request = createMockRequest('user@example.com', { organizationId: 'org-1' })
    const reply = createMockReply()

    await mw(request, reply)

    expect(reply._statusCode).toBe(500)
    expect(reply._body).toEqual({
      error: 'Internal Server Error',
      message: 'Authorization context not initialized',
    })
  })

  it('grants access when user holds the exact permission', async () => {
    const rbacInfo: UserRbacInfo = {
      email: 'user@example.com',
      groups: ['admins'],
      roles: ['admin'],
      permissions: ['rbac:write'],
    }
    const mw = requireServicePermission('rbac:write')
    const request = createMockRequest('user@example.com', { organizationId: 'org-1' }, rbacInfo)
    const reply = createMockReply()

    await mw(request, reply)

    expect(reply.send).not.toHaveBeenCalled()
  })

  it('grants access when user has wildcard *', async () => {
    const rbacInfo: UserRbacInfo = {
      email: 'super@example.com',
      groups: ['super_admins'],
      roles: ['super_admin'],
      permissions: ['*'],
    }
    const mw = requireServicePermission('rbac:write')
    const request = createMockRequest('super@example.com', { organizationId: 'org-1' }, rbacInfo)
    const reply = createMockReply()

    await mw(request, reply)

    expect(reply.send).not.toHaveBeenCalled()
  })

  it('returns 403 when user lacks the required permission', async () => {
    const rbacInfo: UserRbacInfo = {
      email: 'reader@example.com',
      groups: ['readers'],
      roles: ['reader'],
      permissions: ['rbac:read'],
    }
    const mw = requireServicePermission('rbac:write')
    const request = createMockRequest('reader@example.com', { organizationId: 'org-1' }, rbacInfo)
    const reply = createMockReply()

    await mw(request, reply)

    expect(reply._statusCode).toBe(403)
    expect(reply._body).toEqual({
      error: 'Forbidden',
      message: "Permission 'rbac:write' required",
    })
  })

  it('returns 403 when permissions array is empty', async () => {
    const rbacInfo: UserRbacInfo = {
      email: 'noperm@example.com',
      groups: [],
      roles: [],
      permissions: [],
    }
    const mw = requireServicePermission('rbac:write')
    const request = createMockRequest('noperm@example.com', { organizationId: 'org-1' }, rbacInfo)
    const reply = createMockReply()

    await mw(request, reply)

    expect(reply._statusCode).toBe(403)
  })
})
