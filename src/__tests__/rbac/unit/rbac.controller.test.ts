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
  // Real constant (not a stub): the controller validates names against it.
  SERVICE_NAME_PATTERN: /^[a-z0-9_-]+$/,
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
    getAccessRule: vi.fn().mockResolvedValue({ rule: { id: 'rule-1', match: {} } }),
    createAccessRule: vi.fn().mockImplementation(async () => mockState.mutationResult),
    updateAccessRule: vi.fn().mockImplementation(async () => mockState.mutationResult),
    deleteAccessRule: vi.fn().mockImplementation(async () => mockState.mutationResult),
    setOrgServiceMapping: vi.fn().mockResolvedValue(undefined),
  },
}))


// Mock redis-rbac repository (legacy — may still be referenced in other tests)
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
    code: vi.fn().mockImplementation(function (this: typeof reply, code: number) {
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

  describe('setOrgServiceMapping', () => {
    const ORG = '11111111-1111-4111-8111-111111111111'

    it('accepts hyphenated site names (echo-mfa), like the route schema and site publish do', async () => {
      const reply = createMockReply()
      await controller.setOrgServiceMapping(
        createMockRequest({ body: { organizationId: ORG, services: ['echo', 'echo-mfa', 'wallets-api'] } }) as FastifyRequest<{ Body: { organizationId: string; services: string[] } }>,
        reply,
      )
      expect(reply._statusCode).toBe(201)
      expect(rbacService.setOrgServiceMapping).toHaveBeenCalledWith(ORG, ['echo', 'echo-mfa', 'wallets-api'], expect.anything())
    })

    it('still refuses a name outside the service charset, naming the field', async () => {
      const call = controller.setOrgServiceMapping(
        createMockRequest({ body: { organizationId: ORG, services: ['echo', 'Echo MFA'] } }) as FastifyRequest<{ Body: { organizationId: string; services: string[] } }>,
        createMockReply(),
      )
      await expect(call).rejects.toMatchObject({ errors: [expect.objectContaining({ path: ['services', 1] })] })
      expect(rbacService.setOrgServiceMapping).not.toHaveBeenCalled()
    })
  })

  // ===========================================================================
  // Simulate (OPA-backed)
  // ===========================================================================
})
