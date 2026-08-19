import * as k8s from '@kubernetes/client-node'
import { createHash } from 'node:crypto'
import { env } from '../config/index.js'

/**
 * A machine caller authenticated by the cluster's API server.
 *
 * `email` is the SYNTHETIC SUBJECT the rest of the stack authorizes on: the
 * whole authorization chain (requireServiceAdmin → OPA getUserInfo,
 * requireManageableOrg → OPA manageable_orgs, the audit trail) keys off an
 * email, so a ServiceAccount is projected into that namespace rather than
 * given a parallel authorization path. A token that verifies but has no
 * matching Kratos identity resolves to zero permissions → 403.
 */
export interface K8sServiceAccountPrincipal {
  kind: 'k8s-service-account'
  /** Full API-server username, e.g. `system:serviceaccount:acme-prod:provisioner`. */
  username: string
  namespace: string
  serviceAccount: string
  uid: string | null
  /** API-server groups (`system:serviceaccounts`, …) — recorded, never authorized on. */
  groups: string[]
  /** Synthetic subject: `<sa>.<ns>@K8S_SA_EMAIL_DOMAIN`. */
  email: string
}

interface CacheEntry {
  principal: K8sServiceAccountPrincipal | null
  expiresAt: number
}

/**
 * `system:serviceaccount:<namespace>:<name>`.
 * Namespace is a DNS-1123 label; ServiceAccount names additionally allow dots.
 */
const SA_USERNAME_RE =
  /^system:serviceaccount:([a-z0-9]([-a-z0-9]*[a-z0-9])?):([a-z0-9]([-a-z0-9.]*[a-z0-9])?)$/

/** Failed reviews are cached briefly so a token spray can't hammer the API server. */
const NEGATIVE_CACHE_TTL_MS = 10_000
/** Hard cap on cache entries; cleared wholesale past it (tokens are short-lived). */
const CACHE_MAX_ENTRIES = 5_000

/**
 * Kubernetes ServiceAccount token verification via the TokenReview API.
 *
 * jinbe does NOT verify the token signature itself: it hands the token to the
 * cluster's API server, which is the only authority on its own tokens. That
 * also means a projected (bound) token stops working the moment its pod is
 * deleted — revocation is free.
 *
 * jinbe's own ServiceAccount needs `create` on `tokenreviews`
 * (authentication.k8s.io) — the built-in `system:auth-delegator` ClusterRole.
 *
 * FAIL-CLOSED throughout: an unreachable API server, a missing RBAC grant, a
 * non-ServiceAccount username or an audience mismatch all return null, which
 * the identity extractor treats as "not authenticated".
 */
export class K8sTokenReviewService {
  /** `undefined` = not yet initialised, `null` = initialisation failed. */
  private api: k8s.AuthenticationV1Api | null | undefined
  private cache = new Map<string, CacheEntry>()

  /**
   * Cheap, UNVERIFIED discriminator: does this bearer token even claim to be a
   * ServiceAccount token? Keeps unrelated bearer credentials (and junk) from
   * costing an API-server round-trip. The claim is worthless on its own —
   * TokenReview below is what actually decides.
   */
  looksLikeServiceAccountToken(token: string): boolean {
    const parts = token.split('.')
    if (parts.length !== 3) return false
    try {
      const payload = JSON.parse(
        Buffer.from(parts[1], 'base64url').toString('utf8')
      ) as { sub?: unknown }
      return typeof payload.sub === 'string' && payload.sub.startsWith('system:serviceaccount:')
    } catch {
      return false
    }
  }

  /**
   * Verify a bearer token and resolve it to a machine principal.
   * Returns null for any failure — never throws.
   */
  async verify(token: string): Promise<K8sServiceAccountPrincipal | null> {
    if (!env.K8S_SA_AUTH_ENABLED) return null

    const key = createHash('sha256').update(token).digest('hex')
    const hit = this.cache.get(key)
    if (hit && Date.now() < hit.expiresAt) return hit.principal
    if (hit) this.cache.delete(key)

    const principal = await this.review(token)
    this.remember(key, principal, token)
    return principal
  }

  /** Drop all cached decisions (tests, and any future rotation hook). */
  clearCache(): void {
    this.cache.clear()
  }

  private async review(token: string): Promise<K8sServiceAccountPrincipal | null> {
    const authApi = this.authApi()
    if (!authApi) return null

    const audience = env.K8S_SA_TOKEN_AUDIENCE
    let status: k8s.V1TokenReviewStatus | undefined
    try {
      const response = await authApi.createTokenReview({
        body: {
          apiVersion: 'authentication.k8s.io/v1',
          kind: 'TokenReview',
          spec: { token, audiences: [audience] },
        } as k8s.V1TokenReview,
      })
      status = response.status
    } catch (error) {
      console.error(
        '[k8s-token-review] TokenReview call failed (deny):',
        error instanceof Error ? error.message : error
      )
      return null
    }

    if (!status?.authenticated) {
      if (status?.error) {
        console.warn(`[k8s-token-review] token rejected by API server: ${status.error}`)
      }
      return null
    }

    // Audience binding. An authenticated review with an EMPTY audience list
    // means "valid for the API server's own audience" — i.e. a default pod
    // token, not one minted for jinbe. Accepting it would turn every pod's
    // default token into a jinbe credential, so it is rejected here.
    if (!status.audiences?.includes(audience)) {
      console.warn(
        `[k8s-token-review] audience mismatch (want '${audience}', got ${JSON.stringify(status.audiences ?? [])}) — denied`
      )
      return null
    }

    const username = status.user?.username ?? ''
    const match = SA_USERNAME_RE.exec(username)
    if (!match) {
      // A human/OIDC user token is authenticated but is NOT a ServiceAccount;
      // it must not be projected into the machine subject namespace.
      console.warn(
        `[k8s-token-review] authenticated subject is not a ServiceAccount ('${username}') — denied`
      )
      return null
    }

    const namespace = match[1]
    const serviceAccount = match[3]

    if (!this.isAllowedSubject(namespace, serviceAccount)) {
      console.warn(
        `[k8s-token-review] '${namespace}:${serviceAccount}' not in K8S_SA_ALLOWED_SUBJECTS — denied`
      )
      return null
    }

    return {
      kind: 'k8s-service-account',
      username,
      namespace,
      serviceAccount,
      uid: status.user?.uid ?? null,
      groups: status.user?.groups ?? [],
      email: `${serviceAccount}.${namespace}@${env.K8S_SA_EMAIL_DOMAIN}`,
    }
  }

  /** Allowlist check: `ns:sa` exact, or `ns:*` for a whole namespace. */
  private isAllowedSubject(namespace: string, serviceAccount: string): boolean {
    const allowed = env.K8S_SA_ALLOWED_SUBJECTS
    if (allowed.length === 0) return true
    return allowed.includes(`${namespace}:${serviceAccount}`) || allowed.includes(`${namespace}:*`)
  }

  /**
   * Cache the decision. A success never outlives the token's own `exp`, so a
   * cached principal can't survive the credential that produced it.
   */
  private remember(
    key: string,
    principal: K8sServiceAccountPrincipal | null,
    token: string
  ): void {
    let ttl = principal ? env.K8S_SA_CACHE_TTL_MS : NEGATIVE_CACHE_TTL_MS
    if (principal) {
      const expMs = this.tokenExpiryMs(token)
      if (expMs !== null) ttl = Math.min(ttl, Math.max(0, expMs - Date.now()))
    }
    if (ttl <= 0) return

    if (this.cache.size >= CACHE_MAX_ENTRIES) this.cache.clear()
    this.cache.set(key, { principal, expiresAt: Date.now() + ttl })
  }

  /** Unverified `exp` read, used only to SHORTEN the cache TTL. */
  private tokenExpiryMs(token: string): number | null {
    try {
      const payload = JSON.parse(
        Buffer.from(token.split('.')[1], 'base64url').toString('utf8')
      ) as { exp?: unknown }
      return typeof payload.exp === 'number' ? payload.exp * 1000 : null
    } catch {
      return null
    }
  }

  /**
   * Lazily build the API client from jinbe's OWN in-cluster credentials.
   * Falls back to the ambient kubeconfig so local development against a real
   * cluster works; both failures leave `api` null (fail-closed).
   */
  private authApi(): k8s.AuthenticationV1Api | null {
    if (this.api !== undefined) return this.api
    try {
      const kc = new k8s.KubeConfig()
      try {
        kc.loadFromCluster()
      } catch {
        kc.loadFromDefault()
      }
      this.api = kc.makeApiClient(k8s.AuthenticationV1Api)
    } catch (error) {
      console.error(
        '[k8s-token-review] no usable Kubernetes config — ServiceAccount auth disabled:',
        error instanceof Error ? error.message : error
      )
      this.api = null
    }
    return this.api
  }
}

export const k8sTokenReviewService = new K8sTokenReviewService()