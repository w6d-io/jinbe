import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

const mockState = vi.hoisted(() => ({
  env: { NODE_ENV: 'test', DEV_BYPASS_AUTH: false, K8S_SA_AUTH_ENABLED: false, AUTH_COOKIE_ENABLED: true },
  principal: null as { subject: string; email: string | null; name: string | null; organisations: string[] } | null,
  session: null as Record<string, unknown> | null,
}))

vi.mock('../../../config/index.js', () => ({ env: mockState.env }))
vi.mock('../../../config/env.js', () => ({ env: mockState.env }))

vi.mock('../../../services/oidc-bearer.service.js', () => ({
  oidcBearerService: {
    enabled: true,
    looksLikeJwt: vi.fn(() => true),
    verify: vi.fn(async () => mockState.principal),
  },
}))

vi.mock('../../../services/kratos-session.service.js', () => ({
  kratosSessionService: {
    validateSession: vi.fn(async () =>
      mockState.session ? { session: mockState.session } : { session: null, error: 'invalid' }
    ),
  },
  KratosSessionService: {
    extractSessionCookie: vi.fn((h?: string) => (h?.includes('ory_kratos_session') ? 'cookie-value' : null)),
  },
}))

import { extractIdentity } from '../../../middleware/identity-extractor.js'

const SUBJECT = '6a5c8def-38da-4267-b900-7298ed38de91'
const PROVEN_AT = new Date('2026-09-11T16:00:00Z')

const request = (cookie?: string) =>
  ({
    headers: { authorization: 'Bearer a.b.c', ...(cookie ? { cookie } : {}) },
    url: '/api/admin/users/x/groups',
    method: 'PUT',
    log: { debug: vi.fn(), warn: vi.fn(), info: vi.fn() },
  }) as unknown as FastifyRequest

const session = (identityId: string) => ({
  sessionId: 'sess-1',
  email: 'a@b.c',
  identityId,
  expiresAt: new Date(),
  active: true,
  aal: 'aal2',
  authenticatedAt: PROVEN_AT,
  secondFactorAt: PROVEN_AT,
})

describe('a token-proven caller and the second factor', () => {
  beforeEach(() => {
    mockState.principal = { subject: SUBJECT, email: 'a@b.c', name: 'A', organisations: [] }
    mockState.session = null
  })

  it('takes the factor from the session travelling with the token', async () => {
    // Without this the step-up gate can never be satisfied from the console: a token carries no
    // such claim, so proving a factor changes nothing and the operator loops.
    mockState.session = session(SUBJECT)
    const req = request('ory_kratos_session=abc')
    await extractIdentity(req, {} as FastifyReply)
    expect(req.userContext).toMatchObject({
      id: SUBJECT,
      aal: 'aal2',
      secondFactorAt: PROVEN_AT,
      sessionId: 'sess-1',
      authVia: 'session',
    })
  })

  it('refuses a session belonging to somebody else, and stays judged on the token', async () => {
    mockState.session = session('a-different-identity')
    const req = request('ory_kratos_session=abc')
    await extractIdentity(req, {} as FastifyReply)
    expect(req.userContext).toMatchObject({ id: SUBJECT, authVia: 'bearer' })
    expect(req.userContext?.aal).toBeUndefined()
    expect(req.userContext?.secondFactorAt).toBeUndefined()
  })

  it('carries no factor when the token travels alone', async () => {
    const req = request()
    await extractIdentity(req, {} as FastifyReply)
    expect(req.userContext).toMatchObject({ id: SUBJECT, authVia: 'bearer' })
    expect(req.userContext?.secondFactorAt).toBeUndefined()
  })

  it('never lets the session change WHO the caller is', async () => {
    mockState.session = { ...session(SUBJECT), email: 'someone.else@x.io', identityId: SUBJECT }
    const req = request('ory_kratos_session=abc')
    await extractIdentity(req, {} as FastifyReply)
    expect(req.userContext?.email).toBe('a@b.c')
    expect(req.userContext?.id).toBe(SUBJECT)
  })
})
