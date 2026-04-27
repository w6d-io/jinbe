import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// Mock dependencies
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getUserGroups: vi.fn(),
    updateUserGroups: vi.fn(),
  },
  KratosApiError: class KratosApiError extends Error {
    statusCode: number
    constructor(statusCode: number, message: string) {
      super(message)
      this.statusCode = statusCode
      this.name = 'KratosApiError'
    }
  },
}))

vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: {
    getAvailableGroups: vi.fn(),
    validateGroups: vi.fn(),
  },
}))

vi.mock('../../../services/opa.service.js', () => ({
  opalService: {
    getUserInfo: vi.fn(),
  },
}))

vi.mock('../../../config/env.js', () => ({
  env: {
    APP_NAME: 'jinbe',
  },
}))

// Mock rbacResolverService (new direct resolver)
vi.mock('../../../services/rbac-resolver.service.js', () => ({
  rbacResolverService: {
    resolveUserRbac: vi.fn().mockResolvedValue({
      email: 'test@example.com',
      groups: [],
      roles: [],
      permissions: [],
    }),
  },
}))

import { AdminController } from '../../../controllers/admin.controller.js'
import { kratosService, KratosApiError } from '../../../services/kratos.service.js'
import { rbacService } from '../../../services/rbac.service.js'

// Helper to create mock request
function createMockRequest(
  email: string,
  body?: { groups: string[] }
): FastifyRequest<{
  Params: { email: string }
  Body: { groups: string[] }
}> {
  return {
    params: { email },
    body: body || { groups: [] },
    userContext: { email: 'admin@example.com' },
    log: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  } as unknown as FastifyRequest<{
    Params: { email: string }
    Body: { groups: string[] }
  }>
}

// Helper to create mock reply
function createMockReply(): FastifyReply & {
  _statusCode?: number
  _body?: unknown
} {
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
  return reply as unknown as FastifyReply & {
    _statusCode?: number
    _body?: unknown
  }
}

describe('AdminController - User Groups', () => {
  let controller: AdminController

  beforeEach(() => {
    vi.clearAllMocks()
    controller = new AdminController()
  })

  // ===========================================================================
  // getUserGroups
  // ===========================================================================
  describe('getUserGroups', () => {
    it('should return user groups and available groups', async () => {
      vi.mocked(kratosService.getUserGroups).mockResolvedValueOnce(['devs', 'users'])
      vi.mocked(rbacService.getAvailableGroups).mockResolvedValueOnce([
        'super_admins',
        'admins',
        'devs',
        'users',
      ])

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await controller.getUserGroups(request, reply)

      expect(reply.send).toHaveBeenCalledWith({
        email: 'user@example.com',
        groups: ['devs', 'users'],
        availableGroups: ['super_admins', 'admins', 'devs', 'users'],
      })
    })

    it('should return 404 when user not found', async () => {
      vi.mocked(kratosService.getUserGroups).mockRejectedValueOnce(
        new KratosApiError(404, 'User not found: nonexistent@example.com')
      )

      const request = createMockRequest('nonexistent@example.com')
      const reply = createMockReply()

      await controller.getUserGroups(request, reply)

      expect(reply._statusCode).toBe(404)
      expect(reply._body).toEqual({
        error: 'Not Found',
        message: 'User not found: nonexistent@example.com',
      })
    })

    it('should propagate unexpected errors', async () => {
      vi.mocked(kratosService.getUserGroups).mockRejectedValueOnce(
        new Error('Database connection failed')
      )

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await expect(controller.getUserGroups(request, reply)).rejects.toThrow(
        'Database connection failed'
      )
    })
  })

  // ===========================================================================
  // updateUserGroups
  // ===========================================================================
  describe('updateUserGroups', () => {
    it('should update user groups with valid groups', async () => {
      vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
      vi.mocked(kratosService.updateUserGroups).mockResolvedValueOnce({
        id: 'user-123',
        schema_id: 'default',
        state: 'active',
        traits: { email: 'user@example.com' },
        metadata_admin: { groups: ['admins', 'devs'] },
        metadata_public: {},
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      })

      const request = createMockRequest('user@example.com', {
        groups: ['admins', 'devs'],
      })
      const reply = createMockReply()

      await controller.updateUserGroups(request, reply)

      expect(rbacService.validateGroups).toHaveBeenCalledWith(['admins', 'devs'])
      expect(kratosService.updateUserGroups).toHaveBeenCalledWith('user@example.com', [
        'admins',
        'devs',
      ])
      expect(reply._body).toMatchObject({
        email: 'user@example.com',
        groups: ['admins', 'devs'],
      })
      expect((reply._body as { updatedAt: string }).updatedAt).toBeDefined()
    })

    it('should default to ["users"] when empty groups array', async () => {
      vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
      vi.mocked(kratosService.updateUserGroups).mockResolvedValueOnce({
        id: 'user-123',
        schema_id: 'default',
        state: 'active',
        traits: { email: 'user@example.com' },
        metadata_admin: { groups: ['users'] },
        metadata_public: {},
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      })

      const request = createMockRequest('user@example.com', { groups: [] })
      const reply = createMockReply()

      await controller.updateUserGroups(request, reply)

      expect(kratosService.updateUserGroups).toHaveBeenCalledWith('user@example.com', ['users'])
      expect((reply._body as { groups: string[] }).groups).toEqual(['users'])
    })

    it('should return 400 when groups are invalid', async () => {
      vi.mocked(rbacService.validateGroups).mockRejectedValueOnce(
        new Error(
          'Invalid groups: fake_group. Available groups: super_admins, admins, devs, users'
        )
      )

      const request = createMockRequest('user@example.com', {
        groups: ['fake_group'],
      })
      const reply = createMockReply()

      await controller.updateUserGroups(request, reply)

      expect(reply._statusCode).toBe(400)
      expect(reply._body).toEqual({
        error: 'Bad Request',
        message:
          'Invalid groups: fake_group. Available groups: super_admins, admins, devs, users',
      })
    })

    it('should return 404 when user not found', async () => {
      vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
      vi.mocked(kratosService.updateUserGroups).mockRejectedValueOnce(
        new KratosApiError(404, 'User not found: nonexistent@example.com')
      )

      const request = createMockRequest('nonexistent@example.com', {
        groups: ['users'],
      })
      const reply = createMockReply()

      await controller.updateUserGroups(request, reply)

      expect(reply._statusCode).toBe(404)
      expect(reply._body).toEqual({
        error: 'Not Found',
        message: 'User not found: nonexistent@example.com',
      })
    })

    it('should log update with admin email', async () => {
      vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
      vi.mocked(kratosService.updateUserGroups).mockResolvedValueOnce({
        id: 'user-123',
        schema_id: 'default',
        state: 'active',
        traits: { email: 'user@example.com' },
        metadata_admin: { groups: ['devs'] },
        metadata_public: {},
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      })

      const request = createMockRequest('user@example.com', { groups: ['devs'] })
      const reply = createMockReply()

      await controller.updateUserGroups(request, reply)

      expect(request.log.info).toHaveBeenCalledWith(
        { email: 'user@example.com', groups: ['devs'], adminEmail: 'admin@example.com' },
        'Updating user groups'
      )
    })

    it('should propagate unexpected errors', async () => {
      vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
      vi.mocked(kratosService.updateUserGroups).mockRejectedValueOnce(
        new Error('Network timeout')
      )

      const request = createMockRequest('user@example.com', { groups: ['devs'] })
      const reply = createMockReply()

      await expect(controller.updateUserGroups(request, reply)).rejects.toThrow(
        'Network timeout'
      )
    })
  })
})
