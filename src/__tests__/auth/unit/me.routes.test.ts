import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'

const mockState = vi.hoisted(() => ({
  env: { DEV_BYPASS_AUTH: false as boolean, NODE_ENV: 'test' as string, APP_NAME: 'jinbe' },
}))

vi.mock('../../../config/env.js', () => ({ env: mockState.env }))

vi.mock('../../../services/opa.service.js', () => ({
  opaService: { manageableOrgs: vi.fn().mockResolvedValue([]) },
}))

vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: { isSuperAdmin: vi.fn().mockResolvedValue(false) },
}))

vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { getOrgServiceMap: vi.fn().mockResolvedValue({}) },
}))

import { meRoutes } from '../../../routes/me.routes.js'
import { opaService } from '../../../services/opa.service.js'
import { rbacService } from '../../../services/rbac.service.js'
import { redisRbacRepository } from '../../../services/redis-rbac.repository.js'

function createMockRequest(options: {
  validatedSession?: { email: string } | null
  userContext?: { email: string } | null
} = {}): FastifyRequest {
  return {
    validatedSession: options.validatedSession || undefined,
    userContext: options.userContext || undefined,
  } as unknown as FastifyRequest
}

function createMockReply(): FastifyReply & { _statusCode?: number; _body?: unknown } {
  const reply = {
    _statusCode: undefined as number | undefined,
    _body: undefined as unknown,
    status: vi.fn().mockImplementation(function (this: typeof reply, c: number) { this._statusCode = c; return this }),
    send: vi.fn().mockImplementation(function (this: typeof reply, b: unknown) { this._body = b; return this }),
  }
  return reply as unknown as FastifyReply & { _statusCode?: number; _body?: unknown }
}

function createMockFastify(): FastifyInstance & { registeredRoutes: Array<{ method: string; path: string; handler: Function }> } {
  const routes: Array<{ method: string; path: string; handler: Function }> = []
  return {
    registeredRoutes: routes,
    get: vi.fn().mockImplementation((path: string, _opts: unknown, handler: Function) => {
      routes.push({ method: 'GET', path, handler })
    }),
  } as unknown as FastifyInstance & { registeredRoutes: Array<{ method: string; path: string; handler: Function }> }
}

describe('meRoutes — GET /me/organizations', () => {
  let handler: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>

  beforeEach(async () => {
    vi.clearAllMocks()
    mockState.env.DEV_BYPASS_AUTH = false
    mockState.env.NODE_ENV = 'test'
    vi.mocked(opaService.manageableOrgs).mockResolvedValue([])
    vi.mocked(rbacService.isSuperAdmin).mockResolvedValue(false)
    vi.mocked(redisRbacRepository.getOrgServiceMap).mockResolvedValue({})
    const fastify = createMockFastify()
    await meRoutes(fastify)
    handler = fastify.registeredRoutes.find((r) => r.path === '/organizations')!
      .handler as (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
  })

  it('returns the delegated manageable orgs for a non-super-admin', async () => {
    vi.mocked(opaService.manageableOrgs).mockResolvedValue(['org-1', 'org-2'])
    const reply = createMockReply()
    await handler(createMockRequest({ validatedSession: { email: 'a@b.io' } }), reply)

    expect(opaService.manageableOrgs).toHaveBeenCalledWith('a@b.io')
    expect(reply._body).toEqual({ organizations: ['org-1', 'org-2'], scope: 'delegated' })
  })

  it('returns ALL mapped orgs with scope=all for a global super_admin', async () => {
    vi.mocked(rbacService.isSuperAdmin).mockResolvedValue(true)
    vi.mocked(redisRbacRepository.getOrgServiceMap).mockResolvedValue({ 'org-a': 'kuma', 'org-b': 'fleet' })
    const reply = createMockReply()
    await handler(createMockRequest({ validatedSession: { email: 'super@b.io' } }), reply)

    expect(reply._body).toEqual({ organizations: ['org-a', 'org-b'], scope: 'all' })
    // super_admin path does not consult the delegated manageable_orgs
    expect(opaService.manageableOrgs).not.toHaveBeenCalled()
  })

  it('falls back to userContext email when no validated session', async () => {
    vi.mocked(opaService.manageableOrgs).mockResolvedValue(['org-9'])
    const reply = createMockReply()
    await handler(createMockRequest({ userContext: { email: 'c@d.io' } }), reply)

    expect(opaService.manageableOrgs).toHaveBeenCalledWith('c@d.io')
    expect(reply._body).toEqual({ organizations: ['org-9'], scope: 'delegated' })
  })

  it('returns 401 when unauthenticated', async () => {
    const reply = createMockReply()
    await handler(createMockRequest({}), reply)

    expect(reply._statusCode).toBe(401)
    expect(opaService.manageableOrgs).not.toHaveBeenCalled()
  })

  it('ignores the sentinel "unknown" userContext email as unauthenticated', async () => {
    const reply = createMockReply()
    await handler(createMockRequest({ userContext: { email: 'unknown' } }), reply)

    expect(reply._statusCode).toBe(401)
  })

  it('DEV_BYPASS_AUTH returns an empty list without hitting OPA', async () => {
    mockState.env.DEV_BYPASS_AUTH = true
    mockState.env.NODE_ENV = 'development'
    const reply = createMockReply()
    await handler(createMockRequest({ validatedSession: { email: 'dev@b.io' } }), reply)

    expect(reply._body).toEqual({ organizations: [], scope: 'delegated' })
    expect(opaService.manageableOrgs).not.toHaveBeenCalled()
  })
})
