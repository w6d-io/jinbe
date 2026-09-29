import { env } from '../config/index.js'
import { adminAuthHeaders, redactUrl } from './admin-auth.js'

/**
 * Custom error class for Hydra Admin API errors
 */
/** Hydra could not be reached at all (DNS, connection refused, timeout): an outage, not a refusal. */
export class HydraUnavailableError extends Error {
  public readonly url: string
  constructor(url: string, cause: unknown) {
    super(`OAuth2 server (Hydra) unreachable at ${redactUrl(url)}: ${cause instanceof Error ? ((cause as { cause?: { code?: string } }).cause?.code ?? cause.message) : String(cause)}`)
    this.name = 'HydraUnavailableError'
    this.url = redactUrl(url)
  }
}

export class HydraApiError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public details?: unknown
  ) {
    super(message)
    this.name = 'HydraApiError'
  }
}

/** Shape of an OAuth2 client as returned by Hydra's Admin API (subset). */
export interface HydraOAuth2Client {
  client_id: string
  /** Only present in the response to client creation — shown to the caller once. */
  client_secret?: string
  client_name?: string
  grant_types?: string[]
  response_types?: string[]
  scope?: string
  audience?: string[]
  token_endpoint_auth_method?: string
  /** Top-level owner — we set it to the organization id for server-side list filtering. */
  owner?: string
  metadata?: Record<string, unknown>
  created_at?: string
  updated_at?: string
}

export interface CreateClientInput {
  label: string
  /** Space-separated scope list is built from this array. */
  scopes: string[]
  /** An org machine key's organization (mandatory for one); a personal key belongs to no org. */
  organizationId?: string
  createdBy?: string
  audience?: string[]
  /** RFC 3339. Recorded in metadata.expires_at; jinbe and the policy refuse the key past it. */
  expiresAt?: string
  /**
   * A personal key: owned by the user (`owner = user:<id>`), not listed with the org's keys, and
   * acting as that user. Absent = an org machine key.
   */
  personal?: { subject: string; allPermissions?: boolean }
}

/** Hydra's introspection answer (RFC 7662 plus Hydra's `ext`), the fields jinbe reads. */
export interface HydraIntrospection {
  active: boolean
  sub?: string
  client_id?: string
  scope?: string
  aud?: string[]
  exp?: number
  token_use?: string
  ext?: Record<string, unknown>
}

/**
 * Ory Hydra Admin API Service
 *
 * Manages OAuth2 clients (grant_type=client_credentials) that back per-org
 * M2M API keys. The Admin API is private (cluster-internal) and must never be
 * exposed publicly — see the auth stack README ("Admin API is private").
 */
export class HydraService {
  private adminUrl: string
  private adminToken: string | undefined

  constructor() {
    this.adminUrl = env.HYDRA_ADMIN_URL
    this.adminToken = env.HYDRA_ADMIN_TOKEN
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.adminUrl}${path}`

    let response: Response
    try {
      response = await fetch(url, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
          ...adminAuthHeaders(this.adminToken),
        },
      })
    } catch (err) {
      throw new HydraUnavailableError(this.adminUrl, err)
    }

    if (!response.ok) {
      let errorDetails: unknown
      try {
        errorDetails = await response.json()
      } catch {
        errorDetails = await response.text()
      }
      throw new HydraApiError(
        response.status,
        `Hydra API error: ${response.statusText}`,
        errorDetails
      )
    }

    if (response.status === 204) {
      return undefined as T
    }

    return response.json() as Promise<T>
  }

  /**
   * Create a client_credentials OAuth2 client.
   *
   * `metadata.organization_id` is ALWAYS set (mandatory) so the client is
   * intrinsically bound to its owning organization at the Hydra layer, in
   * addition to the mapping persisted in jinbe's database.
   *
   * Returns the full client INCLUDING client_secret — the secret is only ever
   * available here and must be surfaced to the caller exactly once.
   */
  async createClient(input: CreateClientInput): Promise<HydraOAuth2Client> {
    if (!input.personal && !input.organizationId) throw new Error('an org machine key needs its organization')
    const metadata: Record<string, unknown> = {}
    if (input.organizationId) metadata.organization_id = input.organizationId // mandatory for an org key
    if (input.createdBy) metadata.created_by = input.createdBy
    if (input.expiresAt) metadata.expires_at = input.expiresAt
    if (input.personal) {
      metadata.kind = 'personal'
      metadata.subject = input.personal.subject
      // `all`: the key carries whatever its holder holds at each call; `selected`: the stored scopes.
      metadata.scope_mode = input.personal.allPermissions ? 'all' : 'selected'
    }

    const body = {
      client_name: input.label,
      grant_types: ['client_credentials'],
      response_types: ['token'],
      scope: input.scopes.join(' '),
      token_endpoint_auth_method: 'client_secret_post',
      // owner mirrors organization_id so Hydra can filter lists server-side — or names the user, so a
      // personal key is never listed (nor revocable) as one of the org's machine keys.
      owner: input.personal ? `user:${input.personal.subject}` : input.organizationId,
      ...(input.audience?.length ? { audience: input.audience } : {}),
      metadata,
    }

    return this.request<HydraOAuth2Client>('/admin/clients', {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  /** Fetch a client by id (never includes the secret). */
  async getClient(clientId: string): Promise<HydraOAuth2Client> {
    return this.request<HydraOAuth2Client>(
      `/admin/clients/${encodeURIComponent(clientId)}`
    )
  }

  /** List clients owned by an organization (server-side filtered via `owner`). */
  async listClientsByOwner(owner: string, pageSize = 250): Promise<HydraOAuth2Client[]> {
    const params = new URLSearchParams({ owner, page_size: String(pageSize) })
    return this.request<HydraOAuth2Client[]>(`/admin/clients?${params.toString()}`)
  }

  /**
   * Every client, following Hydra's `Link: rel="next"` page tokens. For the policy's client dataset;
   * bounded so a runaway listing cannot grow for ever.
   */
  async listAllClients(pageSize = 500, maxPages = 50): Promise<HydraOAuth2Client[]> {
    const out: HydraOAuth2Client[] = []
    let token: string | null = null
    for (let page = 0; page < maxPages; page++) {
      const params = new URLSearchParams({ page_size: String(pageSize) })
      if (token) params.set('page_token', token)
      const url = `${this.adminUrl}/admin/clients?${params.toString()}`
      let response: Response
      try {
        response = await fetch(url, { headers: { 'Content-Type': 'application/json', ...adminAuthHeaders(this.adminToken) } })
      } catch (err) {
        throw new HydraUnavailableError(this.adminUrl, err)
      }
      if (!response.ok) throw new HydraApiError(response.status, `Hydra API error: ${response.statusText}`)
      out.push(...((await response.json()) as HydraOAuth2Client[]))
      token = nextPageToken(response.headers.get('link'))
      if (!token) break
    }
    return out
  }

  /**
   * A client_credentials token at Hydra's PUBLIC port, for exactly `scopes` and `audience`. A refused
   * secret is HydraApiError 400/401 — the caller maps it to "key refused", never to an outage.
   */
  async clientCredentialsToken(
    clientId: string,
    secret: string,
    scopes: readonly string[],
    audience?: string,
  ): Promise<{ access_token: string; expires_in: number }> {
    const url = `${env.HYDRA_PUBLIC_URL}/oauth2/token`
    // Our clients are created with token_endpoint_auth_method client_secret_post (createClient), so the
    // credentials go in the form body: Hydra refuses Basic for them ("invalid_client").
    const body = new URLSearchParams({ grant_type: 'client_credentials', scope: scopes.join(' '), client_id: clientId, client_secret: secret })
    if (audience) body.set('audience', audience)
    let response: Response
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
        signal: AbortSignal.timeout(5_000),
      })
    } catch (err) {
      throw new HydraUnavailableError(env.HYDRA_PUBLIC_URL, err)
    }
    if (!response.ok) throw new HydraApiError(response.status, `Hydra token endpoint: ${response.statusText}`)
    const token = (await response.json()) as { access_token?: unknown; expires_in?: unknown }
    if (typeof token.access_token !== 'string' || !token.access_token) throw new HydraApiError(502, 'Hydra issued no token')
    return { access_token: token.access_token, expires_in: typeof token.expires_in === 'number' ? token.expires_in : 600 }
  }

  /** RFC 7662 introspection at the admin port. Never cached here — the caller decides for how long. */
  async introspect(token: string): Promise<HydraIntrospection> {
    return this.request<HydraIntrospection>('/admin/oauth2/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token }).toString(),
    })
  }

  /** Delete (revoke) a client. Opaque tokens stop validating on next introspection. */
  async deleteClient(clientId: string): Promise<void> {
    await this.request<void>(`/admin/clients/${encodeURIComponent(clientId)}`, {
      method: 'DELETE',
    })
  }
}

/** The `page_token` of a `Link: <…?page_token=x>; rel="next"` header, or null on the last page. */
export function nextPageToken(link: string | null): string | null {
  if (!link) return null
  for (const part of link.split(',')) {
    const m = /<([^>]+)>\s*;\s*rel="?next"?/.exec(part)
    if (!m) continue
    try {
      return new URL(m[1], 'http://hydra').searchParams.get('page_token')
    } catch {
      return null
    }
  }
  return null
}

export const hydraService = new HydraService()
