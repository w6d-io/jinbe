import { describe, it, expect, beforeEach, vi } from 'vitest'

const mockState = vi.hoisted(() => ({
  env: {
    K8S_SA_AUTH_ENABLED: true as boolean,
    K8S_SA_TOKEN_AUDIENCE: 'jinbe',
    K8S_SA_EMAIL_DOMAIN: 'serviceaccount.cluster.local',
    K8S_SA_ALLOWED_SUBJECTS: [] as string[],
    K8S_SA_CACHE_TTL_MS: 60_000,
  },
  createTokenReview: vi.fn(),
  loadFromClusterThrows: false as boolean,
}))

vi.mock('../../../config/index.js', () => ({ env: mockState.env }))

vi.mock('@kubernetes/client-node', () => {
  class KubeConfig {
    loadFromCluster() {
      if (mockState.loadFromClusterThrows) throw new Error('not running in a cluster')
    }
    loadFromDefault() {}
    makeApiClient() {
      return { createTokenReview: mockState.createTokenReview }
    }
  }
  return { KubeConfig, AuthenticationV1Api: class {} }
})

import { K8sTokenReviewService } from '../../../services/k8s-token-review.service.js'

/** Build an unsigned JWT-shaped token with the given claims. */
function fakeToken(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'RS256' })}.${b64(claims)}.signature`
}

const SA_TOKEN = fakeToken({
  sub: 'system:serviceaccount:acme-prod:provisioner',
  exp: Math.floor(Date.now() / 1000) + 3600,
})

/** A successful TokenReview response for the given username/audience. */
function reviewOk(
  username = 'system:serviceaccount:acme-prod:provisioner',
  audiences: string[] = ['jinbe']
) {
  return {
    status: {
      authenticated: true,
      audiences,
      user: { username, uid: 'sa-uid-1', groups: ['system:serviceaccounts'] },
    },
  }
}

describe('K8sTokenReviewService', () => {
  let service: K8sTokenReviewService

  beforeEach(() => {
    mockState.env.K8S_SA_AUTH_ENABLED = true
    mockState.env.K8S_SA_ALLOWED_SUBJECTS = []
    mockState.loadFromClusterThrows = false
    mockState.createTokenReview.mockReset()
    service = new K8sTokenReviewService()
  })

  describe('looksLikeServiceAccountToken', () => {
    it('accepts a JWT whose sub is a ServiceAccount', () => {
      expect(service.looksLikeServiceAccountToken(SA_TOKEN)).toBe(true)
    })

    it('rejects opaque tokens and non-ServiceAccount subjects', () => {
      expect(service.looksLikeServiceAccountToken('opaque-hydra-token')).toBe(false)
      expect(
        service.looksLikeServiceAccountToken(fakeToken({ sub: 'alice@w6d.io' }))
      ).toBe(false)
      expect(service.looksLikeServiceAccountToken('a.b.c')).toBe(false)
    })
  })

  describe('verify', () => {
    it('maps an authenticated ServiceAccount to the synthetic subject', async () => {
      mockState.createTokenReview.mockResolvedValue(reviewOk())

      const principal = await service.verify(SA_TOKEN)

      expect(principal).toEqual({
        kind: 'k8s-service-account',
        username: 'system:serviceaccount:acme-prod:provisioner',
        namespace: 'acme-prod',
        serviceAccount: 'provisioner',
        uid: 'sa-uid-1',
        groups: ['system:serviceaccounts'],
        email: 'provisioner.acme-prod@serviceaccount.cluster.local',
      })
    })

    it('requests the configured audience in the TokenReview', async () => {
      mockState.createTokenReview.mockResolvedValue(reviewOk())

      await service.verify(SA_TOKEN)

      expect(mockState.createTokenReview).toHaveBeenCalledWith({
        body: expect.objectContaining({
          apiVersion: 'authentication.k8s.io/v1',
          kind: 'TokenReview',
          spec: { token: SA_TOKEN, audiences: ['jinbe'] },
        }),
      })
    })

    it('denies a default pod token (authenticated, but no audience returned)', async () => {
      // An empty status.audiences means "valid for the API server's audience".
      mockState.createTokenReview.mockResolvedValue(reviewOk(undefined, []))

      expect(await service.verify(SA_TOKEN)).toBeNull()
    })

    it('denies a token minted for another audience', async () => {
      mockState.createTokenReview.mockResolvedValue(reviewOk(undefined, ['other-service']))

      expect(await service.verify(SA_TOKEN)).toBeNull()
    })

    it('denies when the API server says the token is not authenticated', async () => {
      mockState.createTokenReview.mockResolvedValue({
        status: { authenticated: false, error: 'token expired' },
      })

      expect(await service.verify(SA_TOKEN)).toBeNull()
    })

    it('denies an authenticated subject that is not a ServiceAccount', async () => {
      mockState.createTokenReview.mockResolvedValue(reviewOk('alice@w6d.io'))

      expect(await service.verify(SA_TOKEN)).toBeNull()
    })

    it('fails closed when the TokenReview call throws', async () => {
      mockState.createTokenReview.mockRejectedValue(new Error('forbidden: tokenreviews'))

      expect(await service.verify(SA_TOKEN)).toBeNull()
    })

    it('returns null when ServiceAccount auth is disabled', async () => {
      mockState.env.K8S_SA_AUTH_ENABLED = false
      mockState.createTokenReview.mockResolvedValue(reviewOk())

      expect(await service.verify(SA_TOKEN)).toBeNull()
      expect(mockState.createTokenReview).not.toHaveBeenCalled()
    })

    it('caches a successful review instead of re-hitting the API server', async () => {
      mockState.createTokenReview.mockResolvedValue(reviewOk())

      const first = await service.verify(SA_TOKEN)
      const second = await service.verify(SA_TOKEN)

      expect(second).toEqual(first)
      expect(mockState.createTokenReview).toHaveBeenCalledTimes(1)

      service.clearCache()
      await service.verify(SA_TOKEN)
      expect(mockState.createTokenReview).toHaveBeenCalledTimes(2)
    })

    it('does not cache a decision for an already-expired token', async () => {
      const expired = fakeToken({
        sub: 'system:serviceaccount:acme-prod:provisioner',
        exp: Math.floor(Date.now() / 1000) - 10,
      })
      mockState.createTokenReview.mockResolvedValue(reviewOk())

      await service.verify(expired)
      await service.verify(expired)

      expect(mockState.createTokenReview).toHaveBeenCalledTimes(2)
    })
  })

  describe('subject allowlist', () => {
    beforeEach(() => {
      mockState.createTokenReview.mockResolvedValue(reviewOk())
    })

    it('denies a ServiceAccount outside the allowlist', async () => {
      mockState.env.K8S_SA_ALLOWED_SUBJECTS = ['other-ns:provisioner']

      expect(await service.verify(SA_TOKEN)).toBeNull()
    })

    it('allows an exact namespace:serviceaccount entry', async () => {
      mockState.env.K8S_SA_ALLOWED_SUBJECTS = ['acme-prod:provisioner']

      expect(await service.verify(SA_TOKEN)).not.toBeNull()
    })

    it('allows a namespace wildcard entry', async () => {
      mockState.env.K8S_SA_ALLOWED_SUBJECTS = ['acme-prod:*']

      expect(await service.verify(SA_TOKEN)).not.toBeNull()
    })
  })

  it('falls back to the ambient kubeconfig when not running in a cluster', async () => {
    mockState.loadFromClusterThrows = true
    mockState.createTokenReview.mockResolvedValue(reviewOk())

    expect(await service.verify(SA_TOKEN)).not.toBeNull()
  })
})