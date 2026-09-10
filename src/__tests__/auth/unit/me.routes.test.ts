import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'

const mockState = vi.hoisted(() => ({
  env: { DEV_BYPASS_AUTH: false as boolean, NODE_ENV: 'test' as string, APP_NAME: 'jinbe' },
}))

vi.mock('../../../config/env.js', () => ({ env: mockState.env }))

vi.mock('../../../services/organisation-store.js', () => ({
  organisationsForSubject: vi.fn().mockResolvedValue([]),
  organisationStoreConfigured: vi.fn().mockReturnValue(true),
  organisationsById: vi.fn().mockResolvedValue([]),
  allOrganisations: vi.fn().mockResolvedValue([]),
  heldOrganisations: vi.fn().mockResolvedValue([]),
}))


vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { getOrgServiceMap: vi.fn().mockResolvedValue({}) },
}))

import { meRoutes } from '../../../routes/me.routes.js'
import { organisationsForSubject } from '../../../services/organisation-store.js'
import { redisRbacRepository } from '../../../services/redis-rbac.repository.js'

function createMockRequest(options: {
  validatedSession?: { email: string } | null
  userContext?: { email: string } | null
} = {}): FastifyRequest {
  const address = options.userContext?.email ?? options.validatedSession?.email
  return {
    validatedSession: options.validatedSession || undefined,
    // The identity travels with the context in a real session, and the directory is keyed on it —
    // a fixture carrying only an address would answer nothing and say nothing about why.
    userContext: options.userContext
      ? { ...options.userContext, id: `subject-of-${options.userContext.email}` }
      : address
        ? ({ email: address, id: `subject-of-${address}` } as never)
        : undefined,
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
    vi.mocked(organisationsForSubject).mockResolvedValue([])
    vi.mocked(redisRbacRepository.getOrgServiceMap).mockResolvedValue({})
    const fastify = createMockFastify()
    await meRoutes(fastify)
    handler = fastify.registeredRoutes.find((r) => r.path === '/organizations')!
      .handler as (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
  })

  it('returns the delegated manageable orgs for a non-super-admin', async () => {
    vi.mocked(organisationsForSubject).mockResolvedValue(['org-1', 'org-2'])
    const reply = createMockReply()
    await handler(createMockRequest({ validatedSession: { email: 'a@b.io' } }), reply)

    expect(organisationsForSubject).toHaveBeenCalled()
    expect(reply._body).toEqual({ organizations: ['org-1', 'org-2'], names: {}, scope: 'delegated' })
  })

  it('answers with MINE, whoever asks — even an administrator', async () => {
    // It used to answer with every organisation for a super admin, so the same URL meant two things
    // depending on the caller, and a `scope` field existed to say which. Every organisation is a
    // separate question now: GET /admin/organizations, which refuses rather than narrowing.
    vi.mocked(organisationsForSubject).mockResolvedValue(['mine'])

    const reply = createMockReply()
    await handler(createMockRequest({ validatedSession: { email: 'root@example.com' } }), reply)

    expect(reply._body).toMatchObject({ organizations: ['mine'] })
    expect((reply._body as { scope?: string }).scope).not.toBe('all')
  })

  it('falls back to userContext email when no validated session', async () => {
    vi.mocked(organisationsForSubject).mockResolvedValue(['org-9'])
    const reply = createMockReply()
    await handler(createMockRequest({ userContext: { email: 'c@d.io' } }), reply)

    expect(organisationsForSubject).toHaveBeenCalled()
    expect(reply._body).toEqual({ organizations: ['org-9'], names: {}, scope: 'delegated' })
  })

  it('returns 401 when unauthenticated', async () => {
    const reply = createMockReply()
    await handler(createMockRequest({}), reply)

    expect(reply._statusCode).toBe(401)
    expect(organisationsForSubject).not.toHaveBeenCalled()
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

    expect(reply._body).toEqual({ organizations: [], names: {}, scope: 'all' })
    expect(organisationsForSubject).not.toHaveBeenCalled()
  })
})
