import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  mutationResult: {
    success: true,
    message: 'Operation completed',
    timestamp: new Date().toISOString(),
  },
}))

// Mock rbac service (Redis-backed, no branch/authorEmail params)
vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: {
    getUsers: vi.fn().mockResolvedValue({
      users: [{ email: 'user@example.com', groupMembership: { admin: true } }],
    }),
    getGroups: vi.fn().mockResolvedValue({
      groups: [{ name: 'admin', services: { jinbe: ['admin'] } }],
    }),
    createGroup: vi.fn().mockImplementation(async () => mockState.mutationResult),
    updateGroup: vi.fn().mockImplementation(async () => mockState.mutationResult),
    deleteGroup: vi.fn().mockImplementation(async () => mockState.mutationResult),
    getServices: vi.fn().mockResolvedValue({
      services: [{ name: 'jinbe', rolesCount: 4, routesCount: 1 }],
    }),
    createService: vi.fn().mockImplementation(async () => mockState.mutationResult),
    deleteService: vi.fn().mockImplementation(async () => mockState.mutationResult),
    getServiceRoles: vi.fn().mockResolvedValue({
      service: 'jinbe',
      roles: [{ name: 'admin', permissions: ['*'] }, { name: 'viewer', permissions: ['read'] }],
    }),
    getAccessRules: vi.fn().mockResolvedValue({ rules: [] }),
    getAccessRule: vi.fn().mockResolvedValue({ rule: { id: 'rule-1', match: {} } }),
    createAccessRule: vi.fn().mockImplementation(async () => mockState.mutationResult),
    updateAccessRule: vi.fn().mockImplementation(async () => mockState.mutationResult),
    deleteAccessRule: vi.fn().mockImplementation(async () => mockState.mutationResult),
  },
}))

// Mock rbac-resolver service
vi.mock('../../../services/rbac-resolver.service.js', () => ({
  rbacResolverService: {
    resolveUserRbac: vi.fn().mockResolvedValue({
      email: 'user@example.com',
      groups: ['admins'],
      roles: ['admin'],
      permissions: ['*'],
    }),
  },
}))

// Mock redis-rbac repository (for simulate endpoint)
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getRouteMap: vi.fn().mockResolvedValue({ rules: [] }),
  },
}))

// Mock redis-client to avoid real connection
vi.mock('../../../services/redis-client.service.js', () => ({
  redisClientService: {
    getClient: vi.fn(),
    isHealthy: vi.fn().mockResolvedValue(true),
    disconnect: vi.fn().mockResolvedValue(undefined),
    isConnected: true,
  },
  getRedisClient: vi.fn(),
}))

// Import after mocking
import { RbacController } from '../../../controllers/rbac.controller.js'
import { rbacService } from '../../../services/rbac.service.js'

// Helper to create mock request
function createMockRequest<T extends object = object>(
  overrides: T & { userContext?: { email: string } } = {} as T
): FastifyRequest & T {
  return {
    query: {},
    params: {},
    body: {},
    userContext: overrides.userContext || { email: 'admin@example.com' },
    log: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
    ...overrides,
  } as unknown as FastifyRequest & T
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

describe('RbacController', () => {
  let controller: RbacController

  beforeEach(() => {
    vi.clearAllMocks()
    mockState.mutationResult = {
      success: true,
      message: 'Operation completed',
      timestamp: new Date().toISOString(),
    }
    controller = new RbacController()
  })

  // ===========================================================================
  // Users
  // ===========================================================================
  describe('getUsers', () => {
    it('should return users with groups', async () => {
      const request = createMockRequest({})
      const reply = createMockReply()

      await controller.getUsers(request, reply)

      expect(rbacService.getUsers).toHaveBeenCalled()
    })
  })

  // ===========================================================================
  // Groups
  // ===========================================================================
  describe('getGroups', () => {
    it('should return all groups', async () => {
      const request = createMockRequest({})
      const reply = createMockReply()

      await controller.getGroups(request, reply)

      expect(rbacService.getGroups).toHaveBeenCalled()
    })
  })

  describe('createGroup', () => {
    it('should create group and return 201', async () => {
      const request = createMockRequest({
        body: { name: 'developers', services: { jinbe: ['developer'] } },
      })
      const reply = createMockReply()

      await controller.createGroup(
        request as FastifyRequest<{
          Body: { name: string; services: Record<string, string[]> }
        }>,
        reply
      )

      expect(reply._statusCode).toBe(201)
      expect(rbacService.createGroup).toHaveBeenCalledWith(
        'developers',
        { jinbe: ['developer'] },
        expect.objectContaining({ email: 'admin@example.com' }),
      )
    })
  })

  describe('updateGroup', () => {
    it('should update group', async () => {
      const request = createMockRequest({
        params: { name: 'developers' },
        body: { services: { jinbe: ['admin'] } },
      })
      const reply = createMockReply()

      await controller.updateGroup(
        request as FastifyRequest<{
          Params: { name: string }
          Body: { services: Record<string, string[]> }
        }>,
        reply
      )

      expect(rbacService.updateGroup).toHaveBeenCalledWith(
        'developers',
        { jinbe: ['admin'] },
        expect.objectContaining({ email: 'admin@example.com' }),
      )
    })
  })

  describe('deleteGroup', () => {
    it('should delete group', async () => {
      const request = createMockRequest({
        params: { name: 'developers' },
      })
      const reply = createMockReply()

      await controller.deleteGroup(
        request as FastifyRequest<{ Params: { name: string } }>,
        reply
      )

      expect(rbacService.deleteGroup).toHaveBeenCalledWith(
        'developers',
        expect.objectContaining({ email: 'admin@example.com' }),
      )
    })
  })

  // ===========================================================================
  // Services
  // ===========================================================================
  describe('getServices', () => {
    it('should return all services', async () => {
      const request = createMockRequest({})
      const reply = createMockReply()

      await controller.getServices(request, reply)

      expect(rbacService.getServices).toHaveBeenCalled()
    })
  })

  describe('createService', () => {
    it('should create service and return 201', async () => {
      const request = createMockRequest({
        body: {
          name: 'new_service',
          displayName: 'New Service',
          upstreamUrl: 'http://localhost:8080',
        },
      })
      const reply = createMockReply()

      await controller.createService(
        request as FastifyRequest<{
          Body: { name: string; displayName?: string; upstreamUrl?: string }
        }>,
        reply
      )

      expect(reply._statusCode).toBe(201)
      expect(rbacService.createService).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'new_service' }),
        expect.objectContaining({ email: 'admin@example.com' }),
      )
    })
  })

  describe('deleteService', () => {
    it('should delete service', async () => {
      const request = createMockRequest({
        params: { name: 'old_service' },
      })
      const reply = createMockReply()

      await controller.deleteService(
        request as FastifyRequest<{ Params: { name: string } }>,
        reply
      )

      expect(rbacService.deleteService).toHaveBeenCalledWith(
        'old_service',
        expect.objectContaining({ email: 'admin@example.com' }),
      )
    })
  })

  describe('getServiceRoles', () => {
    it('should return service roles', async () => {
      const request = createMockRequest({
        params: { name: 'jinbe' },
      })
      const reply = createMockReply()

      await controller.getServiceRoles(
        request as FastifyRequest<{ Params: { name: string } }>,
        reply
      )

      expect(rbacService.getServiceRoles).toHaveBeenCalledWith('jinbe')
    })
  })

  // ===========================================================================
  // Access Rules
  // ===========================================================================
  describe('getAccessRules', () => {
    it('should return all access rules', async () => {
      const request = createMockRequest({})
      const reply = createMockReply()

      await controller.getAccessRules(request, reply)

      expect(rbacService.getAccessRules).toHaveBeenCalled()
    })
  })

  describe('getAccessRule', () => {
    it('should return specific access rule', async () => {
      const request = createMockRequest({
        params: { id: 'rule-1' },
      })
      const reply = createMockReply()

      await controller.getAccessRule(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(rbacService.getAccessRule).toHaveBeenCalledWith('rule-1')
    })
  })

  describe('createAccessRule', () => {
    it('should create access rule and return 201', async () => {
      const rule = {
        id: 'new-rule',
        upstream: { url: 'http://api-service:8080' },
        match: { url: '<http|https>://api.example.com/<.*>', methods: ['GET'] },
        authenticators: [{ handler: 'cookie_session' }],
        authorizer: { handler: 'remote_json' },
        mutators: [{ handler: 'noop' }],
      }
      const request = createMockRequest({
        body: rule,
      })
      const reply = createMockReply()

      await controller.createAccessRule(
        request as FastifyRequest<{ Body: typeof rule }>,
        reply
      )

      expect(reply._statusCode).toBe(201)
      expect(rbacService.createAccessRule).toHaveBeenCalled()
    })
  })

  describe('updateAccessRule', () => {
    it('should update access rule', async () => {
      const rule = {
        id: 'rule-1',
        upstream: { url: 'http://api-service:8080' },
        match: { url: '<http|https>://api.example.com/<.*>', methods: ['GET', 'POST'] },
        authenticators: [{ handler: 'cookie_session' }],
        authorizer: { handler: 'remote_json' },
        mutators: [{ handler: 'noop' }],
      }
      const request = createMockRequest({
        params: { id: 'rule-1' },
        body: rule,
      })
      const reply = createMockReply()

      await controller.updateAccessRule(
        request as FastifyRequest<{
          Params: { id: string }
          Body: typeof rule
        }>,
        reply
      )

      expect(rbacService.updateAccessRule).toHaveBeenCalledWith(
        'rule-1',
        expect.any(Object),
        expect.objectContaining({ email: 'admin@example.com' }),
      )
    })

    it('should return 400 when rule ID mismatch', async () => {
      const rule = {
        id: 'different-rule',
        upstream: { url: 'http://api-service:8080' },
        match: { url: '<http|https>://api.example.com/<.*>', methods: ['GET'] },
        authenticators: [{ handler: 'cookie_session' }],
        authorizer: { handler: 'remote_json' },
        mutators: [{ handler: 'noop' }],
      }
      const request = createMockRequest({
        params: { id: 'rule-1' },
        body: rule,
      })
      const reply = createMockReply()

      await controller.updateAccessRule(
        request as FastifyRequest<{
          Params: { id: string }
          Body: typeof rule
        }>,
        reply
      )

      expect(reply._statusCode).toBe(400)
      expect((reply._body as { error: string }).error).toBe('Bad Request')
    })
  })

  describe('deleteAccessRule', () => {
    it('should delete access rule', async () => {
      const request = createMockRequest({
        params: { id: 'rule-1' },
      })
      const reply = createMockReply()

      await controller.deleteAccessRule(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(rbacService.deleteAccessRule).toHaveBeenCalledWith(
        'rule-1',
        expect.objectContaining({ email: 'admin@example.com' }),
      )
    })
  })
})
