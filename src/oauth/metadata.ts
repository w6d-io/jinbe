import { env } from '../config/index.js'
import { componentLogger } from '../telemetry/logger.js'
import { delegableJinbePermissions } from '../services/platform-scopes.js'
import { issuerUrl, type OAuthIssuer } from './issuer.js'

/**
 * RFC 8414 authorization-server metadata for MCP clients, served by jinbe on the Hydra host
 * (`GET /.well-known/oauth-authorization-server`, rule `mcp-oauth-as`).
 *
 * Hydra publishes only OpenID discovery, and the MCP clients' documented fallback is this document.
 * The endpoints are Hydra's own (read from its discovery, 5 min; derived from the issuer when Hydra
 * cannot be read); the rest says what MCP clients get here and nothing more: the authorization code
 * with PKCE S256 only, public clients, registration through jinbe's locked-down endpoint. Hydra's
 * discovery still lists everything for machine clients (client_credentials), which never read this.
 */

export const MCP_SCOPE = 'mcp'
export const OFFLINE_SCOPE = 'offline_access'

type Endpoints = { authorization_endpoint: string; token_endpoint: string; revocation_endpoint: string; jwks_uri: string }

const TTL_MS = 5 * 60_000
let cached: { at: number; issuer: string; endpoints: Endpoints } | null = null

/** Test seam. */
export function resetOAuthMetadataCache(): void {
  cached = null
}

const derived = (iss: OAuthIssuer): Endpoints => ({
  authorization_endpoint: issuerUrl(iss, 'oauth2/auth'),
  token_endpoint: issuerUrl(iss, 'oauth2/token'),
  revocation_endpoint: issuerUrl(iss, 'oauth2/revoke'),
  jwks_uri: issuerUrl(iss, '.well-known/jwks.json'),
})

async function endpoints(iss: OAuthIssuer, now: number): Promise<Endpoints> {
  if (cached && cached.issuer === iss.issuer && now - cached.at < TTL_MS) return cached.endpoints
  const fallback = derived(iss)
  let out = fallback
  try {
    const res = await fetch(`${env.HYDRA_PUBLIC_URL.replace(/\/+$/, '')}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(3_000) })
    if (res.ok) {
      const doc = (await res.json()) as Record<string, unknown>
      if (doc.issuer !== iss.issuer) {
        // Clients compare this string with the one auth-mcp names: a mismatch breaks every sign-in.
        componentLogger('oauth').error({ hydraIssuer: doc.issuer, configured: iss.issuer }, 'MCP_OAUTH_ISSUER differs from the issuer Hydra publishes')
      }
      const pick = (k: keyof Endpoints) => (typeof doc[k] === 'string' && (doc[k] as string).startsWith(iss.origin) ? (doc[k] as string) : fallback[k])
      out = { authorization_endpoint: pick('authorization_endpoint'), token_endpoint: pick('token_endpoint'), revocation_endpoint: pick('revocation_endpoint'), jwks_uri: pick('jwks_uri') }
    }
  } catch (err) {
    componentLogger('oauth').warn({ reason: (err as Error).message }, 'Hydra discovery unreadable; endpoints derived from the issuer')
  }
  cached = { at: now, issuer: iss.issuer, endpoints: out }
  return out
}

/** `mcp`, `offline_access` and every permission a delegated caller could use on jinbe. */
export function supportedScopes(): string[] {
  return [MCP_SCOPE, OFFLINE_SCOPE, ...[...delegableJinbePermissions().keys()].sort()]
}

export async function authorizationServerMetadata(iss: OAuthIssuer, now: number = Date.now()): Promise<Record<string, unknown>> {
  return {
    issuer: iss.issuer,
    ...(await endpoints(iss, now)),
    registration_endpoint: issuerUrl(iss, 'oauth2/register'),
    scopes_supported: supportedScopes(),
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],
  }
}
