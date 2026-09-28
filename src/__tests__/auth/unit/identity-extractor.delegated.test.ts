import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'
import type { K8sServiceAccountPrincipal } from '../../../services/k8s-token-review.service.js'

// The delegated path takes an opaque Hydra token ONLY together with an allowed actor's
// ServiceAccount token in X-Actor-Token. Either alone is nobody.

const s = vi.hoisted(() => ({
  env: {
    NODE_ENV: 'test' as string,
    DEV_BYPASS_AUTH: false as boolean,
    K8S_SA_AUTH_ENABLED: true as boolean,
    DELEGATED_ACTOR_SUBJECTS: ['auth:auth-mcp'] as string[],
  },
  enabled: true,
  actor: null as K8sServiceAccountPrincipal | null,
  resolve: vi.fn(),
}))

vi.mock('../../../config/index.js', () => ({ env: s.env }))
vi.mock('../../../services/k8s-token-review.service.js', () => ({
  k8sTokenReviewService: {
    looksLikeServiceAccountToken: vi.fn((t: string) => t.split('.').length === 3),
    verify: vi.fn(async () => s.actor),
  },
}))
vi.mock('../../../services/delegated-token.service.js', () => ({
  delegatedTokenService: {
    get enabled() { return s.enabled },
    looksOpaque: (t: string) => t.split('.').length !== 3,
    resolve: s.resolve,
  },
}))
vi.mock('../../../services/kratos-session.service.js', () => ({
  kratosSessionService: { validateSession: vi.fn(async () => ({ session: null, error: 'invalid' })) },
  KratosSessionService: { extractSessionCookie: vi.fn(() => null) },
}))

import { extractIdentity } from '../../../middleware/identity-extractor.js'

const actor = (namespace: string, serviceAccount: string): K8sServiceAccountPrincipal => ({
  kind: 'k8s-service-account', username: `system:serviceaccount:${namespace}:${serviceAccount}`, namespace, serviceAccount,
  uid: 'u', groups: [], email: `${serviceAccount}.${namespace}@serviceaccount.cluster.local`,
})

const req = (headers: Record<string, string>, url = '/api/admin/sites') =>
  ({ headers, url, method: 'GET', log: { debug: vi.fn(), warn: vi.fn(), info: vi.fn() } }) as unknown as FastifyRequest

const PRINCIPAL = { subject: 'user-1', email: 'ann@acme.io', name: 'Ann', clientId: 'claude', scopes: ['sites:read'], org: 'acme', kind: 'oauth', expiresAt: Date.now() + 60_000 }

beforeEach(() => {
  s.enabled = true
  s.actor = actor('auth', 'auth-mcp')
  s.resolve.mockReset().mockResolvedValue({ principal: PRINCIPAL })
})

describe('extractIdentity — delegated tokens', () => {
  it('authenticates the USER, narrowed to the token, with the actor recorded as via', async () => {
    const request = req({ authorization: 'Bearer ory_at_opaque', 'x-actor-token': 'h.p.s' })
    await extractIdentity(request, {} as FastifyReply)
    expect(request.userContext).toEqual({
      email: 'ann@acme.io', id: 'user-1', name: 'Ann', authVia: 'delegated',
      delegation: { clientId: 'claude', scopes: ['sites:read'], org: 'acme', kind: 'oauth', via: 'auth-mcp' },
    })
    // No aal, no second-factor time: a delegated token can never pass a step-up.
    expect(request.userContext?.aal).toBeUndefined()
  })

  it('refuses the token without an actor — a stolen token cannot be replayed directly', async () => {
    const request = req({ authorization: 'Bearer ory_at_opaque' })
    await extractIdentity(request, {} as FastifyReply)
    expect(request.userContext).toBeUndefined()
    expect(request.sessionError).toBe('delegated_token_rejected')
    expect(s.resolve).not.toHaveBeenCalled()
  })

  it('refuses an actor that is not listed, or does not verify', async () => {
    s.actor = actor('default', 'random-pod')
    const a = req({ authorization: 'Bearer ory_at_opaque', 'x-actor-token': 'h.p.s' })
    await extractIdentity(a, {} as FastifyReply)
    expect(a.userContext).toBeUndefined()
    s.actor = null
    const b = req({ authorization: 'Bearer ory_at_opaque', 'x-actor-token': 'h.p.s' })
    await extractIdentity(b, {} as FastifyReply)
    expect(b.userContext).toBeUndefined()
  })

  it('refuses a token the service refuses', async () => {
    s.resolve.mockResolvedValue({ error: 'audience_mismatch' })
    const request = req({ authorization: 'Bearer ory_at_opaque', 'x-actor-token': 'h.p.s' })
    await extractIdentity(request, {} as FastifyReply)
    expect(request.userContext).toBeUndefined()
  })

  it('leaves /api/mcp/* alone: there the token is what is asked about, not the caller', async () => {
    const request = req({ authorization: 'Bearer ory_at_opaque', 'x-actor-token': 'h.p.s' }, '/api/mcp/token-info')
    await extractIdentity(request, {} as FastifyReply)
    expect(request.userContext).toBeUndefined()
    expect(s.resolve).not.toHaveBeenCalled()
  })

  it('does nothing while disabled (the flag defaults off)', async () => {
    s.enabled = false
    const request = req({ authorization: 'Bearer ory_at_opaque', 'x-actor-token': 'h.p.s' })
    await extractIdentity(request, {} as FastifyReply)
    expect(request.userContext).toBeUndefined()
    expect(request.sessionError).toBeUndefined()
  })
})
