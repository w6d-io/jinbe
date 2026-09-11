import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'
import type { K8sServiceAccountPrincipal } from '../../../services/k8s-token-review.service.js'

const mockState = vi.hoisted(() => ({
  env: {
    NODE_ENV: 'test' as string,
    DEV_BYPASS_AUTH: false as boolean,
    K8S_SA_AUTH_ENABLED: true as boolean,
  },
  principal: null as K8sServiceAccountPrincipal | null,
  session: null as Record<string, unknown> | null,
}))

vi.mock('../../../config/index.js', () => ({ env: mockState.env }))

vi.mock('../../../services/k8s-token-review.service.js', () => ({
  k8sTokenReviewService: {
    looksLikeServiceAccountToken: vi.fn((token: string) => token.split('.').length === 3),
    verify: vi.fn(async () => mockState.principal),
  },
}))

vi.mock('../../../services/kratos-session.service.js', () => ({
  kratosSessionService: {
    validateSession: vi.fn(async () =>
      mockState.session
        ? { session: mockState.session, error: undefined }
        : { session: null, error: 'invalid' }
    ),
  },
  KratosSessionService: {
    extractSessionCookie: vi.fn((header?: string) =>
      header?.includes('ory_kratos_session') ? 'cookie-value' : null
    ),
  },
}))

import { extractIdentity } from '../../../middleware/identity-extractor.js'
import { k8sTokenReviewService } from '../../../services/k8s-token-review.service.js'

const PRINCIPAL: K8sServiceAccountPrincipal = {
  kind: 'k8s-service-account',
  username: 'system:serviceaccount:acme-prod:provisioner',
  namespace: 'acme-prod',
  serviceAccount: 'provisioner',
  uid: 'sa-uid-1',
  groups: ['system:serviceaccounts'],
  email: 'provisioner.acme-prod@serviceaccount.cluster.local',
}

function createMockRequest(headers: Record<string, string> = {}): FastifyRequest {
  return {
    headers,
    url: '/api/organizations/org-1/users/u-1',
    method: 'GET',
    log: { debug: vi.fn(), warn: vi.fn(), info: vi.fn() },
  } as unknown as FastifyRequest
}

describe('extractIdentity — Kubernetes ServiceAccount (M2M) branch', () => {
  beforeEach(() => {
    mockState.env.K8S_SA_AUTH_ENABLED = true
    mockState.env.DEV_BYPASS_AUTH = false
    mockState.principal = PRINCIPAL
    mockState.session = null
    vi.mocked(k8sTokenReviewService.verify).mockClear()
  })

  it('authenticates a verified ServiceAccount token as the synthetic subject', async () => {
    const request = createMockRequest({ authorization: 'Bearer head.payload.sig' })

    await extractIdentity(request, {} as FastifyReply)

    expect(request.userContext).toEqual({
      email: 'provisioner.acme-prod@serviceaccount.cluster.local',
      id: 'k8s:sa-uid-1',
      name: 'system:serviceaccount:acme-prod:provisioner',
      // Stamped so the step-up gate refuses under a name that does not invite a re-verification
      // it would never read.
      authVia: 'machine',
    })
    expect(request.machine).toEqual(PRINCIPAL)
    // No human session artefacts — the step-up gate (aal2) can never pass.
    expect(request.validatedSession).toBeUndefined()
    expect(request.userContext?.aal).toBeUndefined()
  })

  it('is case-insensitive about the Bearer scheme', async () => {
    const request = createMockRequest({ authorization: 'bearer head.payload.sig' })

    await extractIdentity(request, {} as FastifyReply)

    expect(request.userContext?.email).toBe(PRINCIPAL.email)
  })

  it('leaves the request unauthenticated when TokenReview rejects the token', async () => {
    mockState.principal = null
    const request = createMockRequest({ authorization: 'Bearer head.payload.sig' })

    await extractIdentity(request, {} as FastifyReply)

    expect(request.userContext).toBeUndefined()
    expect(request.machine).toBeUndefined()
    expect(request.sessionError).toBe('k8s_service_account_token_rejected')
  })

  it('falls through to the session cookie when the bearer token is rejected', async () => {
    mockState.principal = null
    mockState.session = {
      email: 'alice@w6d.io',
      identityId: 'id-1',
      name: 'Alice',
      sessionId: 'sess-1',
      expiresAt: new Date(),
      aal: 'aal2',
      authenticatedAt: new Date(),
    }
    const request = createMockRequest({
      authorization: 'Bearer head.payload.sig',
      cookie: 'ory_kratos_session=abc',
    })

    await extractIdentity(request, {} as FastifyReply)

    expect(request.userContext?.email).toBe('alice@w6d.io')
    expect(request.machine).toBeUndefined()
  })

  it('ignores bearer tokens when ServiceAccount auth is disabled', async () => {
    mockState.env.K8S_SA_AUTH_ENABLED = false
    const request = createMockRequest({ authorization: 'Bearer head.payload.sig' })

    await extractIdentity(request, {} as FastifyReply)

    expect(k8sTokenReviewService.verify).not.toHaveBeenCalled()
    expect(request.userContext).toBeUndefined()
  })

  it('does not attempt a TokenReview for a non-JWT bearer credential', async () => {
    const request = createMockRequest({ authorization: 'Bearer opaque-hydra-token' })

    await extractIdentity(request, {} as FastifyReply)

    expect(k8sTokenReviewService.verify).not.toHaveBeenCalled()
    expect(request.userContext).toBeUndefined()
  })
})