import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose'
import { env } from '../config/index.js'

/**
 * A caller proven by a signed token rather than by a session this service can look up.
 *
 * `organisations` is what the token asserts, which is only read when the deployment says the token
 * decides. It is deliberately not merged with anything local: two authorities on the same question
 * means neither can be trusted when they disagree.
 */
export interface BearerPrincipal {
  readonly subject: string
  readonly email: string | null
  readonly name: string | null
  readonly organisations: readonly string[]
}

/**
 * The organisations a set of claims asserts, whatever shape the issuer chose.
 *
 * Three shapes are accepted because three are in the wild: a list of identifiers, a list of objects
 * carrying one, and a single value. Anything else yields nothing rather than a guess — an
 * authorization input read wrongly is worse than one read as empty, which simply grants nothing.
 *
 * Exported for its own sake: this is the part worth testing, and it has no dependencies.
 */
export function organisationsFromClaims(claims: JWTPayload, claimName: string): string[] {
  const raw = claims[claimName]
  if (typeof raw === 'string') return raw ? [raw] : []
  if (!Array.isArray(raw)) return []
  return raw
    .map((entry) => {
      if (typeof entry === 'string') return entry
      if (entry && typeof entry === 'object') {
        const held = entry as Record<string, unknown>
        const value = held['id'] ?? held['organisationId'] ?? held['organization_id']
        return typeof value === 'string' ? value : ''
      }
      return ''
    })
    .filter((id): id is string => !!id)
}

class OidcBearerService {
  // Built once and kept: the key set is fetched on first use and refreshed by the library on an
  // unknown key id, so a rotation costs one extra fetch rather than a restart.
  private keys: ReturnType<typeof createRemoteJWKSet> | null = null

  /** Whether this deployment is configured to accept bearer tokens at all. */
  get enabled(): boolean {
    return env.AUTH_BEARER_ENABLED && !!env.OIDC_JWKS_URL && !!env.OIDC_ISSUER
  }

  /**
   * Verify a bearer token and describe who it belongs to, or return null.
   *
   * Null on every failure, and never a partial principal: a token that cannot be verified is a
   * token from nobody. The caller decides what to do with that, and nothing here falls back to a
   * weaker check.
   */
  async verify(token: string): Promise<BearerPrincipal | null> {
    if (!this.enabled) return null

    try {
      this.keys ??= createRemoteJWKSet(new URL(env.OIDC_JWKS_URL!))

      const { payload } = await jwtVerify(token, this.keys, {
        issuer: env.OIDC_ISSUER,
        // Only when configured: verifying against an undefined audience would accept any.
        ...(env.OIDC_AUDIENCE ? { audience: env.OIDC_AUDIENCE } : {}),
      })

      // The subject is what the token is about, and there is no caller without one.
      if (typeof payload.sub !== 'string' || !payload.sub) return null

      return {
        subject: payload.sub,
        email: typeof payload.email === 'string' ? payload.email : null,
        name: typeof payload.name === 'string' ? payload.name : null,
        organisations:
          env.ORGANISATION_SOURCE === 'claim'
            ? organisationsFromClaims(payload, env.ORGANISATION_CLAIM)
            : [],
      }
    } catch (error) {
      // Expiry, a wrong issuer, a wrong audience and a bad signature all land here, and all mean
      // the same thing to a caller: not authenticated.
      console.warn(
        `[oidc] bearer rejected: ${error instanceof Error ? error.message : String(error)}`,
      )
      return null
    }
  }

  /**
   * Whether a token even looks like a JWT this service could verify.
   *
   * Used to tell an OIDC token from the other bearer this service accepts, so that neither
   * verification path is handed a token meant for the other.
   */
  looksLikeJwt(token: string): boolean {
    const parts = token.split('.')
    return parts.length === 3 && parts.every((part) => part.length > 0)
  }
}

export const oidcBearerService = new OidcBearerService()
