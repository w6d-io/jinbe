import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  env: {
    APP_NAME: 'jinbe',
  },
  rbacInfo: null as { email: string; groups: string[]; roles: string[]; permissions: string[] } | null,
  // Path 3 hybrid: per-identity organization context returned by
  // kratosService.getOrganizationContext. Default is an identity with
  // no orgs and no legacy pointer; tests override per-case.
  orgContext: {
    primary: null as string | null,
    organizations: [] as string[],
  },
  orgContextError: null as Error | null,
}))

// Mock env
vi.mock('../../../config/env.js', () => ({
  env: mockState.env,
}))

// Mock rbacResolverService
vi.mock('../../../services/rbac-resolver.service.js', () => ({
  rbacResolverService: {
    resolveUserRbac: vi.fn().mockImplementation(async () => mockState.rbacInfo),
  },
}))

// Mock kratosService — whoami calls getOrganizationContext to populate
// the multi-org payload, since /sessions/whoami does NOT expose
// metadata_admin.
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getOrganizationContext: vi.fn().mockImplementation(async () => {
      if (mockState.orgContextError) throw mockState.orgContextError
      return mockState.orgContext
    }),
  },
}))

// Import after mocking
import { whoamiRoutes } from '../../../routes/whoami.routes.js'
import { rbacResolverService } from '../../../services/rbac-resolver.service.js'
import { kratosService } from '../../../services/kratos.service.js'

// Helper types
interface WhoamiResponse {
  authenticated: boolean
  email: string | null
  name: string | null
  picture: string | null
  identity_id: string | null
  session_id: string | null
  error: string | null
  groups: string[]
  roles: string[]
  permissions: string[]
  organization_id: string | null
  organizations: string[]
}

// Helper to create mock request
function createMockRequest(options: {
  validatedSession?: {
    email: string
    sessionId: string
    identityId: string
    name?: string
    picture?: string
  } | null
  userContext?: {
    email: string
    id?: string
    sessionId?: string
    name?: string
  } | null
  sessionError?: string | null
} = {}): FastifyRequest {
  return {
    validatedSession: options.validatedSession || undefined,
    userContext: options.userContext || undefined,
    sessionError: options.sessionError || undefined,
    log: {
      error: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
    },
  } as unknown as FastifyRequest
}

// Helper to create mock reply
function createMockReply(): FastifyReply & { _body?: WhoamiResponse } {
  const reply = {
    _body: undefined as WhoamiResponse | undefined,
    send: vi.fn().mockImplementation(function (this: typeof reply, body: WhoamiResponse) {
      this._body = body
      return this
    }),
  }
  return reply as unknown as FastifyReply & { _body?: WhoamiResponse }
}

// Helper to create mock fastify instance
function createMockFastify(): FastifyInstance & { registeredRoutes: Array<{ method: string; path: string; handler: Function }> } {
  const routes: Array<{ method: string; path: string; handler: Function }> = []
  return {
    registeredRoutes: routes,
    get: vi.fn().mockImplementation((path: string, options: unknown, handler: Function) => {
      routes.push({ method: 'GET', path, handler })
    }),
  } as unknown as FastifyInstance & { registeredRoutes: Array<{ method: string; path: string; handler: Function }> }
}

describe('whoamiRoutes', () => {
  let fastify: ReturnType<typeof createMockFastify>
  let handler: (request: FastifyRequest, reply: FastifyReply) => Promise<void>

  beforeEach(async () => {
    vi.clearAllMocks()

    // Reset mock state
    mockState.rbacInfo = {
      email: 'user@example.com',
      groups: ['users'],
      roles: ['viewer'],
      permissions: ['read'],
    }
    mockState.orgContext = { primary: null, organizations: [] }
    mockState.orgContextError = null

    // Register routes
    fastify = createMockFastify()
    await whoamiRoutes(fastify)

    // Get the handler
    const route = fastify.registeredRoutes.find((r) => r.path === '/whoami')
    handler = route!.handler as (request: FastifyRequest, reply: FastifyReply) => Promise<void>
  })

  describe('GET /whoami', () => {
    it('should return authenticated=true with validated Kratos session', async () => {
      const request = createMockRequest({
        validatedSession: {
          email: 'user@example.com',
          sessionId: 'session-123',
          identityId: 'identity-456',
          name: 'Test User',
          picture: 'https://example.com/avatar.png',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.authenticated).toBe(true)
      expect(reply._body?.email).toBe('user@example.com')
      expect(reply._body?.name).toBe('Test User')
      expect(reply._body?.picture).toBe('https://example.com/avatar.png')
      expect(reply._body?.identity_id).toBe('identity-456')
      expect(reply._body?.session_id).toBe('session-123')
    })

    it('should return authenticated=true with userContext (proxy headers)', async () => {
      const request = createMockRequest({
        userContext: {
          email: 'proxy-user@example.com',
          id: 'proxy-identity',
          sessionId: 'proxy-session',
          name: 'Proxy User',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.authenticated).toBe(true)
      expect(reply._body?.email).toBe('proxy-user@example.com')
      expect(reply._body?.identity_id).toBe('proxy-identity')
    })

    it('should return authenticated=false when no session', async () => {
      const request = createMockRequest({})
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.authenticated).toBe(false)
      expect(reply._body?.email).toBeNull()
    })

    it('should return authenticated=false when userContext email is "unknown"', async () => {
      const request = createMockRequest({
        userContext: {
          email: 'unknown',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.authenticated).toBe(false)
      expect(reply._body?.email).toBeNull()
    })

    it('should resolve RBAC info when email is available', async () => {
      const request = createMockRequest({
        validatedSession: {
          email: 'user@example.com',
          sessionId: 'session-123',
          identityId: 'identity-456',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(rbacResolverService.resolveUserRbac).toHaveBeenCalledWith('user@example.com', 'jinbe')
      expect(reply._body?.groups).toEqual(['users'])
      expect(reply._body?.roles).toEqual(['viewer'])
      expect(reply._body?.permissions).toEqual(['read'])
    })

    it('should not resolve RBAC when no email', async () => {
      const request = createMockRequest({})
      const reply = createMockReply()

      await handler(request, reply)

      expect(rbacResolverService.resolveUserRbac).not.toHaveBeenCalled()
      expect(reply._body?.groups).toEqual([])
      expect(reply._body?.roles).toEqual([])
      expect(reply._body?.permissions).toEqual([])
    })

    it('should handle RBAC resolver errors gracefully', async () => {
      vi.mocked(rbacResolverService.resolveUserRbac).mockRejectedValueOnce(new Error('Service unavailable'))

      const request = createMockRequest({
        validatedSession: {
          email: 'user@example.com',
          sessionId: 'session-123',
          identityId: 'identity-456',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.groups).toEqual([])
      expect(reply._body?.roles).toEqual([])
      expect(reply._body?.permissions).toEqual([])
    })

    it('should include session error if present', async () => {
      const request = createMockRequest({
        sessionError: 'Session validation failed',
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.error).toBe('Session validation failed')
    })

    it('should prefer validatedSession over userContext', async () => {
      const request = createMockRequest({
        validatedSession: {
          email: 'session@example.com',
          sessionId: 'session-123',
          identityId: 'session-identity',
          name: 'Session User',
        },
        userContext: {
          email: 'context@example.com',
          id: 'context-identity',
          name: 'Context User',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.email).toBe('session@example.com')
      expect(reply._body?.identity_id).toBe('session-identity')
      expect(reply._body?.name).toBe('Session User')
    })

    it('should return userContext name when no validatedSession name', async () => {
      const request = createMockRequest({
        validatedSession: {
          email: 'user@example.com',
          sessionId: 'session-123',
          identityId: 'identity-456',
          name: undefined,
        },
        userContext: {
          email: 'user@example.com',
          name: 'Context Name',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.name).toBe('Context Name')
    })

    // ──────────────────────────────────────────────────────────────────
    // Path 3 hybrid: organization_id + organizations payload
    // ──────────────────────────────────────────────────────────────────

    it('returns organizations:[] and organization_id:null for a legacy identity with no orgs', async () => {
      mockState.orgContext = { primary: null, organizations: [] }

      const request = createMockRequest({
        validatedSession: {
          email: 'legacy@example.org',
          sessionId: 'session-1',
          identityId: 'identity-1',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.organizations).toEqual([])
      expect(reply._body?.organization_id).toBeNull()
      expect(kratosService.getOrganizationContext).toHaveBeenCalledWith('identity-1')
    })

    it('returns populated organizations array when metadata_admin.organizations is set', async () => {
      mockState.orgContext = {
        primary: null,
        organizations: [
          '11111111-1111-1111-1111-111111111111',
          '22222222-2222-2222-2222-222222222222',
        ],
      }

      const request = createMockRequest({
        validatedSession: {
          email: 'multi@example.org',
          sessionId: 's',
          identityId: 'identity-multi',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.organizations).toEqual([
        '11111111-1111-1111-1111-111111111111',
        '22222222-2222-2222-2222-222222222222',
      ])
      expect(reply._body?.organization_id).toBeNull()
    })

    it('returns legacy organization_id alongside multi-org array (hybrid path)', async () => {
      mockState.orgContext = {
        primary: '33333333-3333-3333-3333-333333333333',
        organizations: ['11111111-1111-1111-1111-111111111111'],
      }

      const request = createMockRequest({
        validatedSession: {
          email: 'hybrid@example.org',
          sessionId: 's',
          identityId: 'identity-hybrid',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.organization_id).toBe('33333333-3333-3333-3333-333333333333')
      expect(reply._body?.organizations).toEqual([
        '11111111-1111-1111-1111-111111111111',
      ])
    })

    it('returns picture:null when no avatar trait is set', async () => {
      const request = createMockRequest({
        validatedSession: {
          email: 'nopic@example.org',
          sessionId: 's',
          identityId: 'identity-nopic',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.picture).toBeNull()
    })

    it('returns picture URL when set on the session traits', async () => {
      const request = createMockRequest({
        validatedSession: {
          email: 'avatar@example.org',
          sessionId: 's',
          identityId: 'identity-avatar',
          picture: 'https://example.org/u/avatar.png',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.picture).toBe('https://example.org/u/avatar.png')
    })

    it('fails soft when Kratos org-context lookup throws — returns empty orgs, not 500', async () => {
      mockState.orgContextError = new Error('kratos admin api unreachable')

      const request = createMockRequest({
        validatedSession: {
          email: 'transient@example.org',
          sessionId: 's',
          identityId: 'identity-transient',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(reply._body?.authenticated).toBe(true)
      expect(reply._body?.organizations).toEqual([])
      expect(reply._body?.organization_id).toBeNull()
    })

    it('does not call Kratos when there is no identity_id (unauthenticated request)', async () => {
      const request = createMockRequest({})
      const reply = createMockReply()

      await handler(request, reply)

      expect(kratosService.getOrganizationContext).not.toHaveBeenCalled()
      expect(reply._body?.organizations).toEqual([])
      expect(reply._body?.organization_id).toBeNull()
    })
  })
})
