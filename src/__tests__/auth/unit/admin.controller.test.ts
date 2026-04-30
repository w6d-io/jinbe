import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import { createKratosIdentity, testIdentities, createIdentityRequest } from '../fixtures/kratos.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  env: {
    APP_NAME: 'jinbe',
  },
  identities: [] as ReturnType<typeof createKratosIdentity>[],
  opalUserInfo: null as { email: string; groups: string[]; roles: string[]; permissions: string[] } | null,
}))

// Mock env
vi.mock('../../../config/env.js', () => ({
  env: mockState.env,
}))

// Mock kratosService
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    listIdentities: vi.fn().mockImplementation(async () => ({
      identities: mockState.identities,
      nextPageToken: undefined,
    })),
    getIdentity: vi.fn().mockImplementation(async (id: string) => {
      const identity = mockState.identities.find((i) => i.id === id)
      if (!identity) {
        const error = new Error('Not found') as Error & { statusCode: number }
        error.statusCode = 404
        throw error
      }
      return identity
    }),
    createIdentity: vi.fn().mockImplementation(async (data: unknown) => {
      const newIdentity = createKratosIdentity({
        id: '550e8400-e29b-41d4-a716-446655440099',
        traits: (data as { traits: { email: string } }).traits,
      })
      return newIdentity
    }),
    updateIdentity: vi.fn().mockImplementation(async (id: string, data: unknown) => {
      const identity = mockState.identities.find((i) => i.id === id)
      if (!identity) {
        const error = new Error('Not found') as Error & { statusCode: number }
        error.statusCode = 404
        throw error
      }
      return { ...identity, ...(data as object) }
    }),
    deleteIdentity: vi.fn().mockResolvedValue(undefined),
    invalidateGroupsCache: vi.fn(),
  },
}))

// Mock opalService
vi.mock('../../../services/opa.service.js', () => ({
  opalService: {
    getUserInfo: vi.fn().mockImplementation(async () => mockState.opalUserInfo),
  },
}))

// Mock rbacService
vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: {
    getAvailableGroups: vi.fn().mockResolvedValue([]),
    validateGroups: vi.fn().mockResolvedValue(undefined),
    notifyBindingsChanged: vi.fn().mockResolvedValue(undefined),
  },
}))

// Mock rbacResolverService (new direct resolver)
vi.mock('../../../services/rbac-resolver.service.js', () => ({
  rbacResolverService: {
    resolveUserRbac: vi.fn().mockImplementation(async (email: string) => ({
      email,
      groups: mockState.opalUserInfo?.groups || [],
      roles: mockState.opalUserInfo?.roles || [],
      permissions: mockState.opalUserInfo?.permissions || [],
    })),
  },
}))

// Import after mocking
import { AdminController } from '../../../controllers/admin.controller.js'
import { kratosService } from '../../../services/kratos.service.js'
import { opalService } from '../../../services/opa.service.js'
import { rbacResolverService } from '../../../services/rbac-resolver.service.js'

// Helper to create mock request
function createMockRequest<T extends object = object>(
  overrides: Partial<FastifyRequest> & T = {} as T
): FastifyRequest & T {
  return {
    query: {},
    params: {},
    body: {},
    ...overrides,
  } as FastifyRequest & T
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
  return reply as unknown as FastifyReply & { _statusCode?: number; _body?: unknown }
}

describe('AdminController', () => {
  let controller: AdminController

  beforeEach(() => {
    vi.clearAllMocks()

    // Reset mock state
    mockState.identities = [...testIdentities]
    mockState.opalUserInfo = {
      email: 'admin@example.com',
      groups: ['admin'],
      roles: ['admin'],
      permissions: ['*'],
    }

    controller = new AdminController()
  })

  describe('listUsers', () => {
    it('should return list of users with RBAC info', async () => {
      const request = createMockRequest({ query: {} })
      const reply = createMockReply()

      await controller.listUsers(request as FastifyRequest<{ Querystring: object }>, reply)

      expect(reply._body).toBeDefined()
      const body = reply._body as { data: unknown[]; next_page_token?: string }
      expect(body.data).toHaveLength(3)
    })

    it('should enrich identities with RBAC groups', async () => {
      mockState.opalUserInfo = {
        email: 'admin@example.com',
        groups: ['admin', 'superadmin'],
        roles: ['admin'],
        permissions: ['read', 'write', 'admin'],
      }

      const request = createMockRequest({ query: {} })
      const reply = createMockReply()

      await controller.listUsers(request as FastifyRequest<{ Querystring: object }>, reply)

      const body = reply._body as { data: Array<{ groups: string[] }> }
      expect(body.data[0].groups).toContain('admin')
      expect(body.data[0].groups).toContain('superadmin')
    })

    it('should pass pagination parameters to kratosService', async () => {
      const request = createMockRequest({
        query: { page_size: '10', page_token: 'token123' },
      })
      const reply = createMockReply()

      await controller.listUsers(request as FastifyRequest<{ Querystring: object }>, reply)

      expect(kratosService.listIdentities).toHaveBeenCalledWith(10, 'token123', undefined)
    })

    it('should handle empty RBAC info gracefully', async () => {
      mockState.opalUserInfo = null

      const request = createMockRequest({ query: {} })
      const reply = createMockReply()

      await controller.listUsers(request as FastifyRequest<{ Querystring: object }>, reply)

      const body = reply._body as { data: Array<{ groups: string[] }> }
      expect(body.data[0].groups).toEqual([])
    })
  })

  describe('getUser', () => {
    it('should return user by ID with RBAC info', async () => {
      const request = createMockRequest({
        params: { id: '550e8400-e29b-41d4-a716-446655440001' },
      })
      const reply = createMockReply()

      await controller.getUser(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._body).toBeDefined()
      const body = reply._body as { id: string; traits: { email: string }; groups: string[] }
      expect(body.id).toBe('550e8400-e29b-41d4-a716-446655440001')
      expect(body.traits.email).toBe('admin@example.com')
    })

    it('should call kratosService.getIdentity with correct ID', async () => {
      const request = createMockRequest({
        params: { id: '550e8400-e29b-41d4-a716-446655440001' },
      })
      const reply = createMockReply()

      await controller.getUser(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(kratosService.getIdentity).toHaveBeenCalledWith('550e8400-e29b-41d4-a716-446655440001')
    })

    it('should enrich identity with RBAC info from OPAL', async () => {
      mockState.opalUserInfo = {
        email: 'admin@example.com',
        groups: ['developers'],
        roles: ['developer'],
        permissions: ['read'],
      }

      const request = createMockRequest({
        params: { id: '550e8400-e29b-41d4-a716-446655440001' },
      })
      const reply = createMockReply()

      await controller.getUser(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      const body = reply._body as { groups: string[]; roles: string[]; permissions: string[] }
      expect(body.groups).toEqual(['developers'])
      expect(body.roles).toEqual(['developer'])
      expect(body.permissions).toEqual(['read'])
    })
  })

  describe('createUser', () => {
    it('should create new user and return 201', async () => {
      const createData = createIdentityRequest('newuser@example.com', {
        firstName: 'New',
        lastName: 'User',
      })

      const request = createMockRequest({ body: createData })
      const reply = createMockReply()

      await controller.createUser(
        request as FastifyRequest<{ Body: typeof createData }>,
        reply
      )

      expect(reply._statusCode).toBe(201)
      expect(reply._body).toBeDefined()
    })

    it('should call kratosService.createIdentity with request body', async () => {
      const createData = createIdentityRequest('test@example.com')

      const request = createMockRequest({ body: createData })
      const reply = createMockReply()

      await controller.createUser(
        request as FastifyRequest<{ Body: typeof createData }>,
        reply
      )

      expect(kratosService.createIdentity).toHaveBeenCalledWith(createData)
    })
  })

  describe('updateUser', () => {
    it('should update user and return updated identity', async () => {
      const updateData = { traits: { name: 'Updated' } }

      const request = createMockRequest({
        params: { id: '550e8400-e29b-41d4-a716-446655440001' },
        body: updateData,
      })
      const reply = createMockReply()

      await controller.updateUser(
        request as FastifyRequest<{ Params: { id: string }; Body: typeof updateData }>,
        reply
      )

      expect(reply._body).toBeDefined()
    })

    it('should call kratosService.updateIdentity with correct params', async () => {
      const updateData = { state: 'inactive' as const }

      const request = createMockRequest({
        params: { id: '550e8400-e29b-41d4-a716-446655440001' },
        body: updateData,
      })
      const reply = createMockReply()

      await controller.updateUser(
        request as FastifyRequest<{ Params: { id: string }; Body: typeof updateData }>,
        reply
      )

      expect(kratosService.updateIdentity).toHaveBeenCalledWith(
        '550e8400-e29b-41d4-a716-446655440001',
        updateData
      )
    })
  })

  describe('deleteUser', () => {
    it('should delete user and return 204', async () => {
      const request = createMockRequest({
        params: { id: '550e8400-e29b-41d4-a716-446655440001' },
      })
      const reply = createMockReply()

      await controller.deleteUser(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(204)
    })

    it('should call kratosService.deleteIdentity with correct ID', async () => {
      const request = createMockRequest({
        params: { id: '550e8400-e29b-41d4-a716-446655440001' },
      })
      const reply = createMockReply()

      await controller.deleteUser(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(kratosService.deleteIdentity).toHaveBeenCalledWith('550e8400-e29b-41d4-a716-446655440001')
    })
  })

  describe('RBAC enrichment', () => {
    it('should handle identity without email', async () => {
      // Create an identity without email trait
      mockState.identities = [
        {
          id: '550e8400-e29b-41d4-a716-446655440001',
          schema_id: 'default',
          state: 'active',
          traits: {} as { email: string },
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ]

      const request = createMockRequest({ query: {} })
      const reply = createMockReply()

      await controller.listUsers(request as FastifyRequest<{ Querystring: object }>, reply)

      const body = reply._body as { data: Array<{ groups: string[] }> }
      expect(body.data[0].groups).toEqual([])
      // Resolver should not be called for users without email
      expect(rbacResolverService.resolveUserRbac).not.toHaveBeenCalled()
    })

    it('should call rbacResolverService with correct app name', async () => {
      const request = createMockRequest({
        params: { id: '550e8400-e29b-41d4-a716-446655440001' },
      })
      const reply = createMockReply()

      await controller.getUser(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(rbacResolverService.resolveUserRbac).toHaveBeenCalledWith('admin@example.com', 'jinbe')
    })
  })
})
