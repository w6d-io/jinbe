import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

const mockState = vi.hoisted(() => ({
  env: {
    DEV_BYPASS_AUTH: false as boolean,
    NODE_ENV: 'test' as string,
    APP_NAME: 'jinbe',
  },
  held: { groups: [], roles: [], permissions: [] } as {
    groups: string[]
    roles: string[]
    permissions: string[]
  },
  allow: false,
  manageable: [] as string[],
}))

vi.mock('../../../config/env.js', () => ({
  env: mockState.env,
}))

vi.mock('../../../config/index.js', () => ({
  env: mockState.env,
}))

// The gate asks OPA: the gateway's own decision for this request, then what the caller holds.
vi.mock('../../../authz/opa.js', () => ({
  decide: vi.fn().mockImplementation(async () => ({ allow: mockState.allow, reason: mockState.allow ? 'ok' : 'forbidden' })),
  rights: vi.fn().mockImplementation(async () => mockState.held),
  manageableOrgs: vi.fn().mockImplementation(async () => mockState.manageable),
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
import { decide, manageableOrgs, rights } from '../../../authz/opa.js'
import type { UserRbacInfo } from '../../../services/authorization-resolution.js'

function createMockRequest(
  email?: string,
  params?: Record<string, string>,
  rbacInfo?: { email: string; groups: string[]; roles: string[]; permissions: string[] }
): FastifyRequest {
  return {
    // The gate keys on the identity; the address is for the log and the trail. The extractor always
    // sets `id` from a real subject (session identityId, token subject, k8s uid) and never invents
    // one, so a context whose address is the `unknown` sentinel has no identity to speak of — a
    // helper that gave it a plausible id there would hide the 401 this asserts.
    userContext: email
      ? { email, ...(email === 'unknown' ? {} : { id: `subject-of-${email}` }) }
      : undefined,
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
    mockState.held = { groups: [], roles: [], permissions: [] }
    mockState.allow = false
    mockState.manageable = []
  })

  describe('DEV_BYPASS_AUTH mode', () => {
    it('bypasses OPA and grants wildcard permissions when DEV_BYPASS_AUTH=true AND NODE_ENV=development', async () => {
      mockState.env.DEV_BYPASS_AUTH = true
      mockState.env.NODE_ENV = 'development'

      const request = createMockRequest('dev@example.com', { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(decide).not.toHaveBeenCalled()
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

      expect(decide).toHaveBeenCalled()
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

  describe('asking OPA', () => {
    it('asks rbac.decision about this very request — method, path without query, aal', async () => {
      mockState.allow = true
      const request = createMockRequest('user@example.com', { organizationId: 'org-42' })
      ;(request as { url: string }).url = '/api/organizations/org-42/users?limit=5'
      ;(request.userContext as { aal?: string }).aal = 'aal2'
      const reply = createMockReply()

      await requireServiceAdmin('organizationId')(request, reply)

      expect(decide).toHaveBeenCalledWith({
        email: 'user@example.com',
        method: 'GET',
        path: '/api/organizations/org-42/users',
        aal: 'aal2',
        client: false,
      })
      expect(rights).toHaveBeenCalledWith('user@example.com')
    })

    it('returns 503 when OPA cannot be asked, not 403', async () => {
      // "Holds nothing" and "I could not tell" are opposite facts, and a 403 here would read as a
      // missing right rather than as an engine nobody could reach.
      vi.mocked(decide).mockRejectedValueOnce(new Error('OPA is unreachable'))

      const request = createMockRequest('user@example.com', { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(reply._statusCode).toBe(503)
      expect(reply._body).toEqual({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    })

    it('refuses before asking anything when the caller has no identity', async () => {
      const request = createMockRequest(undefined, { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(reply._statusCode).toBe(401)
      expect(decide).not.toHaveBeenCalled()
    })
  })

  describe('authorization checks', () => {
    it('admits and attaches what the caller holds when OPA allows', async () => {
      mockState.allow = true
      mockState.held = { groups: ['admins'], roles: ['admin'], permissions: ['rbac:read'] }

      const request = createMockRequest('user@example.com', { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(reply.send).not.toHaveBeenCalled()
      expect(request.rbacInfo).toEqual({ email: 'user@example.com', ...mockState.held })
    })

    it('returns 403 when OPA refuses, whatever the caller holds elsewhere', async () => {
      mockState.allow = false
      mockState.held = { groups: ['admins'], roles: ['admin'], permissions: ['*'] }

      const request = createMockRequest('user@example.com', { organizationId: 'org-1' })
      const reply = createMockReply()

      await requireServiceAdmin()(request, reply)

      expect(reply._statusCode).toBe(403)
      expect(reply._body).toMatchObject({ error: 'Forbidden' })
    })

    it('adds the org-admin set only with orgAdmin and only for an org OPA lists as manageable', async () => {
      mockState.allow = true
      mockState.manageable = ['org-1']

      const plain = createMockRequest('user@example.com', { organizationId: 'org-1' })
      await requireServiceAdmin()(plain, createMockReply())
      expect(plain.rbacInfo?.permissions).toEqual([])
      expect(manageableOrgs).not.toHaveBeenCalled()

      const admin = createMockRequest('user@example.com', { organizationId: 'org-1' })
      await requireServiceAdmin('organizationId', { orgAdmin: true })(admin, createMockReply())
      expect(admin.rbacInfo?.roles).toContain('org_admin')
      expect(admin.rbacInfo?.permissions).toEqual(['org:manage_api_keys', 'org:manage_users', 'users:create', 'users:read'])

      const other = createMockRequest('user@example.com', { organizationId: 'org-2' })
      await requireServiceAdmin('organizationId', { orgAdmin: true })(other, createMockReply())
      expect(other.rbacInfo?.permissions).toEqual([])
    })
  })
})

describe('requireServicePermission factory', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockState.env.DEV_BYPASS_AUTH = false
    mockState.env.NODE_ENV = 'test'
    mockState.held = { groups: [], roles: [], permissions: [] }
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
