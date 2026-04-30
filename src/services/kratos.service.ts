import { env } from '../config/index.js'
import {
  KratosIdentity,
  KratosIdentityCreate,
  KratosIdentityUpdate,
} from '../schemas/admin.schema.js'

/**
 * Custom error class for Kratos API errors
 */
export class KratosApiError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public details?: unknown
  ) {
    super(message)
    this.name = 'KratosApiError'
  }
}

interface ListIdentitiesResponse {
  identities: KratosIdentity[]
  nextPageToken?: string
}

interface IdentityGroupsCache {
  data: Map<string, string[]> // email → groups
  expiresAt: number
}

/**
 * Kratos Admin API Service
 * Manages user identities via Ory Kratos Admin API
 */
export class KratosService {
  private adminUrl: string
  private identityGroupsCache: IdentityGroupsCache | null = null
  private readonly CACHE_TTL_MS = 5_000 // 5 seconds — short TTL as fallback; explicit invalidation handles mutations

  constructor() {
    this.adminUrl = env.KRATOS_ADMIN_URL
  }

  /**
   * Make HTTP request to Kratos Admin API
   */
  private async request<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.adminUrl}${path}`

    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    })

    // Handle non-2xx responses
    if (!response.ok) {
      let errorDetails: unknown
      try {
        errorDetails = await response.json()
      } catch {
        errorDetails = await response.text()
      }

      throw new KratosApiError(
        response.status,
        `Kratos API error: ${response.statusText}`,
        errorDetails
      )
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return undefined as T
    }

    return response.json() as Promise<T>
  }

  /**
   * List all identities with optional pagination
   */
  async listIdentities(
    pageSize?: number,
    pageToken?: string,
    credentialsIdentifier?: string
  ): Promise<ListIdentitiesResponse> {
    const params = new URLSearchParams()

    if (pageSize) {
      params.append('page_size', pageSize.toString())
    }
    if (pageToken) {
      params.append('page_token', pageToken)
    }
    if (credentialsIdentifier) {
      params.append('credentials_identifier', credentialsIdentifier)
    }

    const queryString = params.toString()
    const path = `/admin/identities${queryString ? `?${queryString}` : ''}`

    const identities = await this.request<KratosIdentity[]>(path)

    // Extract next page token from Link header if available
    // For simplicity, we return the identities array directly
    return {
      identities,
      nextPageToken: undefined, // Kratos uses Link headers for pagination
    }
  }

  /**
   * Get identity by ID
   */
  async getIdentity(id: string): Promise<KratosIdentity> {
    return this.request<KratosIdentity>(`/admin/identities/${id}`)
  }

  /**
   * Create new identity
   */
  async createIdentity(data: KratosIdentityCreate): Promise<KratosIdentity> {
    return this.request<KratosIdentity>('/admin/identities', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  /**
   * Update identity by ID
   */
  async updateIdentity(
    id: string,
    data: KratosIdentityUpdate
  ): Promise<KratosIdentity> {
    // Kratos requires a PUT with the full identity object
    // First get the current identity, then merge with updates
    const currentIdentity = await this.getIdentity(id)

    const updatedData = {
      schema_id: data.schema_id ?? currentIdentity.schema_id,
      state: data.state ?? currentIdentity.state,
      traits: {
        ...currentIdentity.traits,
        ...data.traits,
      },
      metadata_public:
        data.metadata_public ?? currentIdentity.metadata_public ?? undefined,
      metadata_admin:
        data.metadata_admin ?? currentIdentity.metadata_admin ?? undefined,
    }

    return this.request<KratosIdentity>(`/admin/identities/${id}`, {
      method: 'PUT',
      body: JSON.stringify(updatedData),
    })
  }

  /**
   * Patch identity via JSON Patch (RFC 6902)
   * Required for fields like organization_id that Kratos ignores on PUT
   */
  async patchIdentity(
    id: string,
    patches: Array<{ op: string; path: string; value: unknown }>
  ): Promise<KratosIdentity> {
    return this.request<KratosIdentity>(`/admin/identities/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(patches),
    })
  }

  /**
   * Delete identity by ID
   */
  async deleteIdentity(id: string): Promise<void> {
    await this.request<void>(`/admin/identities/${id}`, {
      method: 'DELETE',
    })
  }

  /**
   * Send a recovery email to the identity's email address via the Kratos
   * self-service recovery flow (triggers courier). Only /admin/recovery/code
   * and /admin/recovery/link do NOT send email — they return codes for admin
   * to share manually. To actually dispatch an email we must use the public API.
   */
  async sendRecoveryEmail(identityId: string): Promise<void> {
    // Resolve the identity's email first
    const identity = await this.request<KratosIdentity>(`/admin/identities/${identityId}`)
    const email = identity.traits?.email as string | undefined
    if (!email) throw new Error(`Identity ${identityId} has no email trait`)

    const publicUrl = env.KRATOS_PUBLIC_URL

    // 1. Initiate a recovery flow via the public API
    const flowResp = await fetch(`${publicUrl}/self-service/recovery/api`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    })
    if (!flowResp.ok) throw new Error(`Failed to init recovery flow: ${flowResp.status}`)
    const flow = await flowResp.json() as { id: string }

    // 2. Submit the email — Kratos queues the courier message
    const submitResp = await fetch(
      `${publicUrl}/self-service/recovery?flow=${flow.id}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ email, method: 'link' }),
      }
    )
    if (!submitResp.ok && submitResp.status !== 422) {
      throw new Error(`Recovery email submit failed: ${submitResp.status}`)
    }
    // 422 = "sent to email" state (expected for code method)
  }

  /** @deprecated Use sendRecoveryEmail. Returns admin link without sending email. */
  async createRecoveryLink(identityId: string): Promise<{ recovery_link: string; expires_at: string }> {
    return this.request<{ recovery_link: string; expires_at: string }>('/admin/recovery/link', {
      method: 'POST',
      body: JSON.stringify({ identity_id: identityId, expires_in: '24h' }),
    })
  }

  /**
   * List active sessions for an identity
   */
  async listIdentitySessions(identityId: string): Promise<unknown[]> {
    return this.request<unknown[]>(`/admin/identities/${identityId}/sessions`)
  }

  /**
   * Revoke a single session
   */
  async revokeSession(sessionId: string): Promise<void> {
    await this.request<void>(`/admin/sessions/${sessionId}`, { method: 'DELETE' })
  }

  /**
   * Revoke all sessions for an identity
   */
  async revokeAllIdentitySessions(identityId: string): Promise<void> {
    await this.request<void>(`/admin/identities/${identityId}/sessions`, { method: 'DELETE' })
  }

  /**
   * Get all identities with their groups from metadata_admin
   * Results are cached for 30 seconds to avoid hammering Kratos on every OPAL poll
   *
   * @returns Map of email → groups array
   */
  async getAllIdentitiesWithGroups(): Promise<Map<string, string[]>> {
    // Return cached data if valid
    if (
      this.identityGroupsCache &&
      Date.now() < this.identityGroupsCache.expiresAt
    ) {
      return this.identityGroupsCache.data
    }

    const result = new Map<string, string[]>()

    // Fetch all identities (no pagination token handling since Kratos uses Link headers)
    const response = await this.listIdentities(250)

    for (const identity of response.identities) {
      const email = identity.traits?.email as string
      // Extract groups from metadata_admin, default to ['users'] if not set
      const metadataAdmin = identity.metadata_admin as
        | { groups?: string[] }
        | null
        | undefined
      const groups = metadataAdmin?.groups || ['users']

      if (email) {
        result.set(email, groups)
      }
    }

    // Update cache
    this.identityGroupsCache = {
      data: result,
      expiresAt: Date.now() + this.CACHE_TTL_MS,
    }

    return result
  }

  /**
   * Invalidate the identity groups cache
   * Call this after updating user groups to ensure OPAL gets fresh data
   */
  invalidateGroupsCache(): void {
    this.identityGroupsCache = null
  }

  /**
   * Get a single user's groups by email
   * @param email - User's email address
   * @returns Array of group names (defaults to ['users'] if not set)
   */
  async getUserGroups(email: string): Promise<string[]> {
    const response = await this.listIdentities(1, undefined, email)

    if (response.identities.length === 0) {
      throw new KratosApiError(404, `User not found: ${email}`)
    }

    const identity = response.identities[0]
    const metadataAdmin = identity.metadata_admin as
      | { groups?: string[] }
      | null
      | undefined
    return metadataAdmin?.groups || ['users']
  }

  /**
   * Update a user's groups in metadata_admin
   * @param email - User's email address
   * @param groups - Array of group names to assign
   * @returns Updated identity
   */
  async updateUserGroups(
    email: string,
    groups: string[]
  ): Promise<KratosIdentity> {
    // Find identity by email
    const response = await this.listIdentities(1, undefined, email)

    if (response.identities.length === 0) {
      throw new KratosApiError(404, `User not found: ${email}`)
    }

    const identity = response.identities[0]

    // Update metadata_admin.groups while preserving other metadata
    const currentMetadataAdmin = (identity.metadata_admin || {}) as Record<
      string,
      unknown
    >
    const updatedMetadataAdmin = {
      ...currentMetadataAdmin,
      groups,
    }

    const result = await this.updateIdentity(identity.id, {
      metadata_admin: updatedMetadataAdmin,
    })

    // Invalidate cache so OPAL gets fresh data
    this.invalidateGroupsCache()

    return result
  }

  /**
   * List identities filtered by Kratos organization_id (native server-side filtering)
   */
  async listIdentitiesByOrganization(
    organizationId: string,
    pageSize?: number,
    pageToken?: string
  ): Promise<ListIdentitiesResponse> {
    const params = new URLSearchParams()
    params.append('organization_id', organizationId)
    if (pageSize) params.append('page_size', pageSize.toString())
    if (pageToken) params.append('page_token', pageToken)

    const identities = await this.request<KratosIdentity[]>(
      `/admin/identities?${params.toString()}`
    )

    return { identities, nextPageToken: undefined }
  }

  /**
   * Remove a specific group from all users who have it
   * Used when deleting a group to clean up orphaned references
   * @param groupName - Name of the group to remove
   * @returns Number of users updated
   */
  async removeGroupFromAllUsers(groupName: string): Promise<number> {
    const identitiesWithGroups = await this.getAllIdentitiesWithGroups()
    let updatedCount = 0

    for (const [email, groups] of identitiesWithGroups) {
      if (groups.includes(groupName)) {
        const newGroups = groups.filter((g) => g !== groupName)
        // Ensure user always has at least ['users'] group
        const finalGroups = newGroups.length > 0 ? newGroups : ['users']
        await this.updateUserGroups(email, finalGroups)
        updatedCount++
      }
    }

    return updatedCount
  }
}

export const kratosService = new KratosService()
