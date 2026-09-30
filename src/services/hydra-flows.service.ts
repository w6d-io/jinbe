import { hydraService, type HydraOAuth2Client } from './hydra.service.js'

/**
 * Hydra's login and consent flows and consent sessions (admin API) — jinbe is the login/consent
 * provider for MCP clients (src/oauth/). Same admin path and token as client management
 * (hydra.service.ts); errors are the same HydraApiError / HydraUnavailableError.
 */

/** GET /admin/oauth2/auth/requests/login — the fields jinbe reads. */
export interface HydraLoginRequest {
  challenge: string
  client: HydraOAuth2Client
  request_url: string
  requested_scope?: string[]
  requested_access_token_audience?: string[]
  skip?: boolean
  subject?: string
}

/** GET /admin/oauth2/auth/requests/consent — the fields jinbe reads. */
export interface HydraConsentRequest {
  challenge: string
  client: HydraOAuth2Client
  request_url?: string
  requested_scope?: string[]
  requested_access_token_audience?: string[]
  skip?: boolean
  subject?: string
  context?: Record<string, unknown>
}

/** One entry of GET /admin/oauth2/auth/sessions/consent. */
export interface HydraConsentSession {
  consent_request?: HydraConsentRequest
  grant_scope?: string[]
  grant_access_token_audience?: string[]
  handled_at?: string
  session?: { access_token?: Record<string, unknown>; id_token?: Record<string, unknown> }
}

export interface AcceptLoginBody {
  subject: string
  remember: boolean
  acr?: string
  amr?: string[]
  context?: Record<string, unknown>
}

export interface AcceptConsentBody {
  grant_scope: string[]
  grant_access_token_audience: string[]
  remember: boolean
  session: { access_token: Record<string, unknown>; id_token: Record<string, unknown> }
}

export interface RejectBody {
  error: string
  error_description?: string
}

type Redirect = { redirect_to: string }

const q = (name: string, value: string) => `${name}=${encodeURIComponent(value)}`

export const hydraFlows = {
  getLoginRequest: (challenge: string) =>
    hydraService.request<HydraLoginRequest>(`/admin/oauth2/auth/requests/login?${q('login_challenge', challenge)}`),

  acceptLogin: (challenge: string, body: AcceptLoginBody) =>
    hydraService.request<Redirect>(`/admin/oauth2/auth/requests/login/accept?${q('login_challenge', challenge)}`, { method: 'PUT', body: JSON.stringify(body) }),

  rejectLogin: (challenge: string, body: RejectBody) =>
    hydraService.request<Redirect>(`/admin/oauth2/auth/requests/login/reject?${q('login_challenge', challenge)}`, { method: 'PUT', body: JSON.stringify(body) }),

  getConsentRequest: (challenge: string) =>
    hydraService.request<HydraConsentRequest>(`/admin/oauth2/auth/requests/consent?${q('consent_challenge', challenge)}`),

  acceptConsent: (challenge: string, body: AcceptConsentBody) =>
    hydraService.request<Redirect>(`/admin/oauth2/auth/requests/consent/accept?${q('consent_challenge', challenge)}`, { method: 'PUT', body: JSON.stringify(body) }),

  rejectConsent: (challenge: string, body: RejectBody) =>
    hydraService.request<Redirect>(`/admin/oauth2/auth/requests/consent/reject?${q('consent_challenge', challenge)}`, { method: 'PUT', body: JSON.stringify(body) }),

  /** The subject's consent sessions (bounded: one page of 500 — an MCP user has a handful). */
  listConsentSessions: async (subject: string): Promise<HydraConsentSession[]> => {
    const list = await hydraService.request<unknown>(`/admin/oauth2/auth/sessions/consent?${q('subject', subject)}&page_size=500`)
    return Array.isArray(list) ? (list as HydraConsentSession[]) : []
  },

  /** Revokes the (subject, client) consent and every access and refresh token it issued. */
  revokeConsentSessions: (subject: string, clientId: string) =>
    hydraService.request<void>(`/admin/oauth2/auth/sessions/consent?${q('subject', subject)}&${q('client', clientId)}`, { method: 'DELETE' }),

  /** Creates a client with the body as given (the DCR shim forces every field itself). */
  createClient: (body: Record<string, unknown>) =>
    hydraService.request<HydraOAuth2Client>('/admin/clients', { method: 'POST', body: JSON.stringify(body) }),

  /** RFC 6902 JSON Patch; a failed `test` op answers 400 (HydraApiError). */
  patchClient: (clientId: string, patch: readonly Record<string, unknown>[]) =>
    hydraService.request<HydraOAuth2Client>(`/admin/clients/${encodeURIComponent(clientId)}`, { method: 'PATCH', body: JSON.stringify(patch) }),
}
