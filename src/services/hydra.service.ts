import { env } from '../config/index.js'

/**
 * Custom error class for Hydra Admin API errors
 */
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
  organizationId: string
  createdBy?: string
  audience?: string[]
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

  constructor() {
    this.adminUrl = env.HYDRA_ADMIN_URL
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.adminUrl}${path}`

    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    })

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
    const metadata: Record<string, unknown> = {
      organization_id: input.organizationId, // mandatory
    }
    if (input.createdBy) metadata.created_by = input.createdBy

    const body = {
      client_name: input.label,
      grant_types: ['client_credentials'],
      response_types: ['token'],
      scope: input.scopes.join(' '),
      token_endpoint_auth_method: 'client_secret_post',
      // owner mirrors organization_id so Hydra can filter lists server-side.
      owner: input.organizationId,
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

  /** Delete (revoke) a client. Opaque tokens stop validating on next introspection. */
  async deleteClient(clientId: string): Promise<void> {
    await this.request<void>(`/admin/clients/${encodeURIComponent(clientId)}`, {
      method: 'DELETE',
    })
  }
}

export const hydraService = new HydraService()
