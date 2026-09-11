import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  env: {
    APP_NAME: 'jinbe',
  },
  rbacInfo: null as { email: string; groups: string[]; roles: string[]; permissions: string[] } | null,
}))

// Mock env
vi.mock('../../../config/env.js', () => ({
  env: mockState.env,
}))

// What this session holds, from the model the engine decides against — keyed on the IDENTITY. What
// it replaces resolved Kratos metadata and Redis roles from the ADDRESS, and answered `super_admin`
// and `*`: two names this model does not define.
vi.mock('../../../services/authorization-model.service.js', () => ({
  platformRightsOf: vi.fn().mockImplementation(async () => mockState.rbacInfo),
}))

// Mock kratosService — the whoami handler best-effort extends the session
// (WS6). Mock it so the test never touches the real Kratos client (and so we
// can assert the fire-and-forget call).
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    extendSession: vi.fn().mockResolvedValue(undefined),
  },
}))

// Import after mocking
import { whoamiRoutes } from '../../../routes/whoami.routes.js'
import { platformRightsOf } from '../../../services/authorization-model.service.js'
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

    it('resolves what the session holds from the identity, never the address', async () => {
      // An address changes hands; the identity does not. Keyed on the address, a console painted
      // itself from whatever the previous holder had been granted.
      const request = createMockRequest({
        validatedSession: {
          email: 'user@example.com',
          sessionId: 'session-123',
          identityId: 'identity-456',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(platformRightsOf).toHaveBeenCalledWith('identity-456')
      expect(reply._body?.groups).toEqual(['users'])
      expect(reply._body?.roles).toEqual(['viewer'])
      expect(reply._body?.permissions).toEqual(['read'])
    })

    it('resolves nothing without an identity to key on', async () => {
      const request = createMockRequest({})
      const reply = createMockReply()

      await handler(request, reply)

      expect(platformRightsOf).not.toHaveBeenCalled()
      expect(reply._body?.groups).toEqual([])
      expect(reply._body?.roles).toEqual([])
      expect(reply._body?.permissions).toEqual([])
    })

    it('still says who you are when the model cannot be read', async () => {
      vi.mocked(platformRightsOf).mockRejectedValueOnce(new Error('the model could not be read'))

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

    it('should best-effort extend the Kratos session when authenticated (WS6)', async () => {
      const request = createMockRequest({
        validatedSession: {
          email: 'user@example.com',
          sessionId: 'session-123',
          identityId: 'identity-456',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      expect(kratosService.extendSession).toHaveBeenCalledWith('session-123')
      expect(kratosService.extendSession).toHaveBeenCalledTimes(1)
    })

    it('should NOT extend the session when there is no session (WS6)', async () => {
      const request = createMockRequest({})
      const reply = createMockReply()

      await handler(request, reply)

      expect(kratosService.extendSession).not.toHaveBeenCalled()
    })

    it('should still return 200 when the session extend rejects (fire-and-forget)', async () => {
      vi.mocked(kratosService.extendSession).mockRejectedValueOnce(new Error('kratos down'))

      const request = createMockRequest({
        validatedSession: {
          email: 'user@example.com',
          sessionId: 'session-123',
          identityId: 'identity-456',
        },
      })
      const reply = createMockReply()

      await handler(request, reply)

      // whoami must not break on a failed extend
      expect(reply._body?.authenticated).toBe(true)
      expect(kratosService.extendSession).toHaveBeenCalledWith('session-123')
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
  })
})
