import { env } from '../config/index.js'
import { KratosSessionService, kratosSessionService, type ValidatedSession } from '../services/kratos-session.service.js'
import { HydraApiError, HydraUnavailableError, type HydraOAuth2Client } from '../services/hydra.service.js'
import { AuthzUnavailableError, rights } from '../authz/opa.js'
import { groupAllowed } from '../mcp/settings.js'
import { MCP_CLIENT_KIND } from './register.js'
import type { OAuthGate } from './issuer.js'

/**
 * What the login and consent providers share: their answers to login-ui, the checks both repeat
 * (the gate, the client, the request Hydra is holding), and how Hydra's failures map to answers.
 */

export type FlowAnswer =
  | { action: 'redirect'; to: string }
  | { action: 'refused'; reason: RefusalReason; to: string }

export type RefusalReason =
  | 'mcp_disabled'
  | 'oauth_disabled'
  | 'group_not_allowed'
  | 'not_mcp_client'
  | 'pkce_required'
  | 'invalid_target'
  | 'client_bound_elsewhere'
  | 'wrong_account'

/** An answer that is not a flow step: status + body for the route. */
export class FlowError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message)
    this.name = 'FlowError'
  }
}

/** OAuth error codes Hydra hands to the client on a refusal. */
export const REFUSAL_OAUTH_ERROR: Record<RefusalReason, string> = {
  mcp_disabled: 'access_denied',
  oauth_disabled: 'access_denied',
  group_not_allowed: 'access_denied',
  not_mcp_client: 'unauthorized_client',
  pkce_required: 'invalid_request',
  invalid_target: 'invalid_target',
  client_bound_elsewhere: 'access_denied',
  wrong_account: 'login_required',
}

export const REFUSAL_DESCRIPTION: Record<RefusalReason, string> = {
  mcp_disabled: 'AI assistants (MCP) are turned off by an administrator.',
  oauth_disabled: 'Signing in to AI assistants with a browser is turned off by an administrator.',
  group_not_allowed: 'AI assistants are not enabled for your groups.',
  not_mcp_client: 'This application may not sign in here.',
  pkce_required: 'The application must use PKCE with S256.',
  invalid_target: 'The application asked for a resource this server does not issue tokens for.',
  client_bound_elsewhere: 'This application registration belongs to another account. Reconnect from your application.',
  wrong_account: 'Sign in again with the account this application used.',
}

/** A Hydra failure as a FlowError; anything else is rethrown. */
export function hydraFailure(err: unknown): never {
  if (err instanceof HydraApiError && [400, 404, 409, 410].includes(err.statusCode)) {
    throw new FlowError(404, 'challenge_unknown', 'This sign-in request has expired or was already used. Start again from your application.')
  }
  if (err instanceof HydraApiError || err instanceof HydraUnavailableError || err instanceof AuthzUnavailableError) {
    throw new FlowError(503, 'unavailable', 'Signing in is unavailable right now. Try again later.')
  }
  throw err
}

/** The auth host's origin (login-ui + Kratos); every redirect built here starts with it. */
export function authOriginOrFail(): string {
  if (!env.AUTH_DOMAIN) throw new FlowError(503, 'unavailable', 'The sign-in host is not configured.')
  return `https://${env.AUTH_DOMAIN}`
}

/** The visitor's Kratos session, asked of Kratos now (never the read cache): null when signed out. */
export async function visitorSession(cookieHeader: string | undefined): Promise<ValidatedSession | null> {
  const cookie = KratosSessionService.extractSessionCookie(cookieHeader)
  if (!cookie) return null
  return (await kratosSessionService.validateSession(cookie)).session
}

export const isMcpClient = (client: HydraOAuth2Client | undefined): boolean => client?.metadata?.kind === MCP_CLIENT_KIND

/** The PKCE and resource checks on the /oauth2/auth request Hydra is holding. */
export function requestProblem(requestUrl: string | undefined, audience: string, opts: { pkce: boolean }): RefusalReason | null {
  let params: URLSearchParams
  try {
    params = new URL(requestUrl ?? '', 'https://invalid.local').searchParams
  } catch {
    return opts.pkce ? 'pkce_required' : null
  }
  // Belt and braces with Hydra's oauth2.pkce.enforced: its discovery still lists `plain`.
  if (opts.pkce && (params.get('code_challenge_method') !== 'S256' || !params.get('code_challenge'))) return 'pkce_required'
  // RFC 8707: Hydra ignores `resource`, so a client naming another one is refused rather than handed
  // a token for ours.
  const resources = params.getAll('resource')
  if (resources.some((r) => r !== audience)) return 'invalid_target'
  return null
}

/** The gate's refusal (MCP off, OAuth off), the person's groups, or null. */
export async function gateRefusal(gate: OAuthGate, email?: string): Promise<RefusalReason | null> {
  if (gate.on === false) {
    if (gate.reason === 'unavailable') throw new FlowError(503, 'unavailable', 'The AI assistant settings cannot be read right now.')
    return gate.reason
  }
  if (email !== undefined) {
    try {
      if (!groupAllowed(gate.settings, (await rights(email)).groups)) return 'group_not_allowed'
    } catch (err) {
      hydraFailure(err)
    }
  }
  return null
}

/** `http://localhost:53682/callback` → `localhost:53682`, for "an app on this computer". */
export function redirectHost(client: HydraOAuth2Client | undefined): string | null {
  const first = client?.redirect_uris?.[0]
  if (!first) return null
  try {
    return new URL(first).host
  } catch {
    return null
  }
}
