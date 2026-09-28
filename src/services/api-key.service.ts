import { hydraService, HydraApiError, HydraOAuth2Client } from './hydra.service.js'
import { ApiKeyCreateBody, ApiKeyView, ApiKeySecretView } from '../schemas/api-key.schema.js'
import { scopeCatalog } from './api-key-scopes.js'
import { isGrantableScope } from './authorization-resolution.js'
import { apiClientsChanged } from './api-clients.js'
import { forgetApiKeyUse } from './api-key-last-used.js'

/** Raised for caller-facing validation/authorization failures. */
export class ApiKeyError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public details?: unknown
  ) {
    super(message)
    this.name = 'ApiKeyError'
  }
}

interface CreateArgs {
  organizationId: string
  body: ApiKeyCreateBody
  /** Kratos identity id of the admin performing the action. */
  createdBy?: string
  /** Their address: the catalog is what THEY hold in this org. */
  callerEmail: string
}

const DAY_MS = 24 * 60 * 60 * 1000

/** RFC 3339 `days` from now, or undefined. */
export function expiryFrom(days: number | undefined, now = Date.now()): string | undefined {
  return days === undefined ? undefined : new Date(now + days * DAY_MS).toISOString()
}

export function orgOf(client: HydraOAuth2Client): string | undefined {
  return (client.metadata as Record<string, unknown> | undefined)?.organization_id as
    | string
    | undefined
}

export function toView(client: HydraOAuth2Client): ApiKeyView {
  const meta = (client.metadata || {}) as Record<string, unknown>
  return {
    client_id: client.client_id,
    organization_id: (meta.organization_id as string) ?? client.owner ?? '',
    label: client.client_name ?? '',
    scopes: client.scope ? client.scope.split(' ').filter(Boolean) : [],
    created_by: (meta.created_by as string) ?? null,
    created_at: client.created_at ?? null,
    expires_at: typeof meta.expires_at === 'string' ? meta.expires_at : null,
    last_used_at: null,
    created_by_email: null,
  }
}

/** A personal key, whatever org it names: never one of the org's machine keys. */
export function isPersonal(client: HydraOAuth2Client): boolean {
  return (client.metadata as Record<string, unknown> | undefined)?.kind === 'personal'
}

/**
 * API-key (Hydra OAuth2 client) management.
 *
 * Hydra is the single source of truth — jinbe keeps NO local copy (its MongoDB
 * is optional/disabled in most envs). Every client carries a mandatory
 * `metadata.organization_id` and a mirrored `owner` for server-side listing.
 *
 * Security invariants (auth stack Hydra spec §6):
 *  - Requested scopes validated server-side against the allowed catalog.
 *  - `metadata.organization_id` is mandatory on every client.
 *  - The client_secret is returned to the caller exactly once, never stored.
 *  - Mutations verify the client belongs to the org (via Hydra metadata), not
 *    the request path.
 */
export class ApiKeyService {
  /**
   * Validate requested scopes ⊆ this org's catalog for this caller (services/api-key-scopes.ts).
   * Throws 400 on violation. A wildcard is refused before the catalog is even read.
   */
  async validateScopes(
    organizationId: string,
    callerEmail: string,
    scopes: string[],
    catalog: (org: string, email: string) => Promise<{ scope: string }[]> = scopeCatalog,
  ): Promise<void> {
    const wildcard = scopes.filter((s) => !isGrantableScope(s))
    const allowed = new Set((await catalog(organizationId, callerEmail)).map((e) => e.scope))
    const invalid = [...new Set([...wildcard, ...scopes.filter((s) => !allowed.has(s))])]
    if (invalid.length > 0) {
      throw new ApiKeyError(400, 'One or more requested scopes are not allowed', {
        invalid_scopes: invalid,
        allowed_scopes: [...allowed],
      })
    }
  }

  /** Fetch a client and assert it belongs to the org (404 otherwise). */
  private async getOwned(organizationId: string, clientId: string): Promise<HydraOAuth2Client> {
    let client: HydraOAuth2Client
    try {
      client = await hydraService.getClient(clientId)
    } catch (err) {
      if (err instanceof HydraApiError && err.statusCode === 404) {
        throw new ApiKeyError(404, 'API key not found in this organization')
      }
      throw err
    }
    if (orgOf(client) !== organizationId || isPersonal(client)) {
      throw new ApiKeyError(404, 'API key not found in this organization')
    }
    return client
  }

  async create({ organizationId, body, createdBy, callerEmail }: CreateArgs): Promise<ApiKeySecretView> {
    const scopes = [...new Set(body.scopes)]
    await this.validateScopes(organizationId, callerEmail, scopes)

    const client = await hydraService.createClient({
      label: body.label,
      scopes,
      organizationId, // -> mandatory metadata.organization_id + owner
      createdBy,
      audience: body.audience,
      expiresAt: expiryFrom(body.expires_in_days),
    })
    apiClientsChanged('api_key.created')

    return { ...toView(client), created_by_email: createdBy && callerEmail ? callerEmail : null, client_secret: client.client_secret ?? '' }
  }

  async list(organizationId: string): Promise<ApiKeyView[]> {
    const clients = await hydraService.listClientsByOwner(organizationId)
    // Defensive: only surface client_credentials clients owned by this org.
    return clients.filter((c) => orgOf(c) === organizationId && !isPersonal(c)).map(toView)
  }

  /** Get one key, scoped to the org (404 if not owned by it). */
  async get(organizationId: string, clientId: string): Promise<ApiKeyView> {
    return toView(await this.getOwned(organizationId, clientId))
  }

  /** Revoke a key: verify org ownership, then delete the Hydra client. */
  async revoke(organizationId: string, clientId: string): Promise<void> {
    await this.getOwned(organizationId, clientId)
    await hydraService.deleteClient(clientId)
    forgetApiKeyUse(clientId)
    apiClientsChanged('api_key.revoked')
  }

  /**
   * Resolve the owning organization for a client_id. Used by upstream services
   * (Hydra spec §5.3 Option A) to map an X-Client-Id header to a tenant.
   * Returns null when unknown.
   */
  async resolveOrganization(
    clientId: string
  ): Promise<{ organization_id: string; scopes: string[] } | null> {
    let client: HydraOAuth2Client
    try {
      client = await hydraService.getClient(clientId)
    } catch (err) {
      if (err instanceof HydraApiError && err.statusCode === 404) return null
      throw err
    }
    const organization_id = orgOf(client)
    if (!organization_id) return null
    return {
      organization_id,
      scopes: client.scope ? client.scope.split(' ').filter(Boolean) : [],
    }
  }
}

export const apiKeyService = new ApiKeyService()
