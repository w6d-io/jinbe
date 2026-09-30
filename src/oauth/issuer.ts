import { env } from '../config/index.js'
import { mcpGate, type McpSettings } from '../mcp/settings.js'

/**
 * The OAuth authorization server MCP clients sign in with (Hydra), as this deployment names it.
 *
 * MCP_OAUTH_ISSUER is used BYTE-FOR-BYTE: RFC 8414 §3.3 has clients compare the metadata's `issuer`
 * with the one they started from (auth-mcp's PRM `authorization_servers[0]`), and Hydra publishes its
 * issuer with a trailing slash. Paths hung off it (`oauth2/register`) are joined without doubling it.
 */
export interface OAuthIssuer {
  issuer: string
  /** host[:port] — the only Host the metadata and registration answer on. */
  host: string
  origin: string
}

export function oauthIssuer(raw: string = env.MCP_OAUTH_ISSUER): OAuthIssuer | null {
  const issuer = String(raw ?? '').trim()
  if (!issuer) return null
  try {
    const u = new URL(issuer)
    if (u.protocol !== 'https:' || u.search || u.hash || u.username || u.password) return null
    return { issuer, host: u.host, origin: u.origin }
  } catch {
    return null
  }
}

/** `<issuer>` + `path`, one slash between them whatever the issuer ends with. */
export function issuerUrl(iss: OAuthIssuer, path: string): string {
  return `${iss.issuer.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`
}

/** The auth host's origin (login-ui, Kratos), from AUTH_DOMAIN. Null when unset. */
export function authOrigin(): string | null {
  return env.AUTH_DOMAIN ? `https://${env.AUTH_DOMAIN}` : null
}

/**
 * Whether browser sign-in is open now: the MCP ceiling and switch (mcp/settings.ts), an issuer
 * configured, and the administrator's OAuth switch (on by default whenever MCP is on).
 */
export type OAuthGate =
  | { on: true; settings: McpSettings; issuer: OAuthIssuer }
  | { on: false; reason: 'mcp_disabled' | 'oauth_disabled' | 'unavailable'; settings?: McpSettings }

export async function oauthGate(): Promise<OAuthGate> {
  const gate = await mcpGate()
  if (gate.off === 'unavailable') return { on: false, reason: 'unavailable' }
  if (!gate.on) return { on: false, reason: 'mcp_disabled', ...(gate.settings ? { settings: gate.settings } : {}) }
  const issuer = oauthIssuer()
  if (!issuer || !gate.settings.oauth.enabled) return { on: false, reason: 'oauth_disabled', settings: gate.settings }
  return { on: true, settings: gate.settings, issuer }
}
