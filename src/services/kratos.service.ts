import { env } from '../config/index.js'
import { withRedisLock } from './redis-lock.js'
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

/**
 * Per-identity RBAC binding extracted from Kratos, keyed by email.
 *   groups              → metadata_admin.groups (defaults to ['users'])
 *   organizations       → metadata_admin.organizations (multi-org membership;
 *                          defaults to [] — no writer yet, populated by the
 *                          org-delegation phase)
 *   primaryOrganization → the native Kratos `organization_id` (falls back to
 *                          traits.organization_id), or null when unset
 */
export interface IdentityBinding {
  groups: string[]
  organizations: string[]
  primaryOrganization: string | null
  /** identity.state === 'active'. Captured cheaply in the light walk for stats. */
  active: boolean
  /** id + display name, captured for admin substring search (no new PII store). */
  id: string
  name: string | null
}

interface IdentityBindingsCache {
  data: Map<string, IdentityBinding> // email → binding
  expiresAt: number
}

/**
 * Kratos Admin API Service
 * Manages user identities via Ory Kratos Admin API
 */
export class KratosService {
  private adminUrl: string
  private identityBindingsCache: IdentityBindingsCache | null = null
  private readonly CACHE_TTL_MS = 5_000 // 5 seconds — short TTL as fallback; explicit invalidation handles mutations

  constructor() {
    this.adminUrl = env.KRATOS_ADMIN_URL
  }

  /**
   * fetch() with a bounded per-request timeout via AbortController. A hung
   * upstream (connection open but no response) aborts after
   * env.KRATOS_REQUEST_TIMEOUT_MS and the promise rejects, so callers fail
   * closed instead of hanging forever (e.g. the OPAL /bindings directory
   * walk). The timer is always cleared to avoid leaking handles.
   */
  private async fetchWithTimeout(
    url: string,
    options: RequestInit = {}
  ): Promise<Response> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), env.KRATOS_REQUEST_TIMEOUT_MS)
    try {
      return await fetch(url, { ...options, signal: controller.signal })
    } finally {
      clearTimeout(timer)
    }
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
    credentialsIdentifier?: string,
    includeCredential?: ('password' | 'totp' | 'webauthn' | 'lookup_secret' | 'oidc')[],
    organizationId?: string,
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
    if (organizationId) {
      params.append('organization_id', organizationId)
    }
    // include_credential pulls each named credential into the
    // identity.credentials map. Without it Kratos hides the field
    // entirely, even on /admin/identities, so MFA enrichment requires
    // an explicit opt-in.
    if (includeCredential?.length) {
      for (const c of includeCredential) {
        params.append('include_credential', c)
      }
    }

    const queryString = params.toString()
    const path = `/admin/identities${queryString ? `?${queryString}` : ''}`

    // Direct fetch (not the shared request helper) so we can read the Link
    // header Kratos uses to paginate — callers need the next page token.
    // Timeout-bounded so a hung Kratos aborts and the /bindings walk fails
    // closed rather than hanging the OPAL datasource fetch.
    const response = await this.fetchWithTimeout(`${this.adminUrl}${path}`, {
      headers: { 'Content-Type': 'application/json' },
    })
    if (!response.ok) {
      let details: unknown
      try {
        details = await response.json()
      } catch {
        details = await response.text()
      }
      throw new KratosApiError(
        response.status,
        `Kratos API error: ${response.statusText}`,
        details
      )
    }
    const identities = (await response.json()) as KratosIdentity[]
    return {
      identities,
      nextPageToken: this.parseNextPageToken(response.headers?.get('link') ?? null),
    }
  }

  /**
   * Extract the `page_token` of the rel="next" entry from a Kratos Link header
   * (RFC 5988), e.g. `</admin/identities?page_size=250&page_token=ABC>; rel="next"`.
   * Returns undefined when there is no next page.
   */
  private parseNextPageToken(linkHeader: string | null): string | undefined {
    if (!linkHeader) return undefined
    for (const part of linkHeader.split(',')) {
      const rel = part.match(/<([^>]+)>\s*;\s*rel="next"/)
      if (rel) {
        const tok = rel[1].match(/[?&]page_token=([^&>]+)/)
        if (tok) return decodeURIComponent(tok[1])
      }
    }
    return undefined
  }

  /**
   * Get identity by ID
   */
  async getIdentity(id: string): Promise<KratosIdentity> {
    return this.request<KratosIdentity>(`/admin/identities/${id}`)
  }

  /**
   * Returns true if the identity has at least one second-factor credential
   * configured: TOTP, WebAuthn (security key), or backup codes (lookup_secret).
   *
   * Kratos must be queried with include_credential to expose them in the
   * response — without it the credentials map is hidden and we'd always
   * see "no MFA". The endpoint accepts repeated query params per type.
   */
  async hasMFA(id: string): Promise<boolean> {
    const params = new URLSearchParams()
    params.append('include_credential', 'totp')
    params.append('include_credential', 'webauthn')
    params.append('include_credential', 'lookup_secret')
    const identity = await this.request<KratosIdentity>(`/admin/identities/${id}?${params.toString()}`)
    return this.mfaFromCredentials(identity.credentials)
  }

  /**
   * True only when an identity has a REAL enrolled second factor. Shared by
   * hasMFA() and the user-list MFA column (rbac.service.getUsers) so the two
   * can't diverge — a divergent copy here was reporting false positives.
   *
   * Kratos auto-creates credentials.webauthn (just a `user_handle`) for every
   * identity whose schema declares webauthn as an identifier — before any key
   * is registered. Checking credential *key presence* therefore returns true
   * for users who never enrolled, defeating the privilege-escalation MFA gate.
   * Inspect each credential's config for the real enrolment artefact instead:
   *   totp:          config.totp_url            (set on enrol)
   *   webauthn:      config.credentials[]       (registered keys; a lone user_handle doesn't count)
   *   lookup_secret: config.recovery_codes[]    (generated codes)
   *
   * Requires the identity to have been fetched with include_credential for
   * these types; otherwise credentials is hidden and this returns false.
   */
  mfaFromCredentials(credentials: unknown): boolean {
    const creds = (credentials || {}) as Record<
      string,
      { config?: Record<string, unknown> } | undefined
    >
    const totpReg = !!creds.totp?.config?.totp_url
    const webauthnReg = Array.isArray((creds.webauthn?.config as any)?.credentials) &&
      ((creds.webauthn?.config as any).credentials.length > 0)
    const lookupReg = Array.isArray((creds.lookup_secret?.config as any)?.recovery_codes) &&
      ((creds.lookup_secret?.config as any).recovery_codes.length > 0)
    return totpReg || webauthnReg || lookupReg
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

    // 2. Submit the email — Kratos queues the courier message.
    // This cluster's Kratos enables ONLY the `code` recovery strategy (the
    // `link` method is not configured, and password login is disabled →
    // passwordless/code). Submitting `method: 'link'` is rejected and NO email
    // is ever queued, which is why invited users received nothing. Request
    // `code` to match the deployed selfservice.methods config.
    const submitResp = await fetch(
      `${publicUrl}/self-service/recovery?flow=${flow.id}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ email, method: 'code' }),
      }
    )
    if (!submitResp.ok && submitResp.status !== 422) {
      throw new Error(`Recovery email submit failed: ${submitResp.status}`)
    }
    // 200 with a "sent_email" UI state means the code mail is queued; Kratos
    // deliberately does not reveal whether the account exists (422 tolerated).
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
   * Get all identities with their full RBAC binding (groups + organizations +
   * primary organization) from a SINGLE paginated directory scan. Cached for
   * CACHE_TTL_MS so repeated OPAL polls don't hammer Kratos.
   *
   * This is the one place the directory is walked; getAllIdentitiesWithGroups
   * and the OPAL /bindings feed both project from this, so the notion of "who
   * is in what" cannot drift between the group and organization views.
   *
   * Paginate through ALL identities by following Kratos's Link header.
   * Capping at a single page silently drops every member past it (e.g. admins
   * beyond the first page) from the RBAC bindings OPA consumes, causing
   * spurious 403s once the directory grows past one page.
   *
   * @returns Map of email → { groups, organizations, primaryOrganization }
   */
  async getAllIdentitiesWithBindings(): Promise<Map<string, IdentityBinding>> {
    // Return cached data if valid
    if (
      this.identityBindingsCache &&
      Date.now() < this.identityBindingsCache.expiresAt
    ) {
      return this.identityBindingsCache.data
    }

    const result = new Map<string, IdentityBinding>()

    let pageToken: string | undefined
    for (let page = 0; page < 1000; page++) {
      const response = await this.listIdentities(500, pageToken)

      for (const identity of response.identities) {
        const email = identity.traits?.email as string
        if (!email) continue

        // Groups + multi-org membership live in metadata_admin (same place as
        // groups). organizations has no writer yet — the delegation phase
        // populates it — so it defaults to [] until then.
        const metadataAdmin = identity.metadata_admin as
          | { groups?: string[]; organizations?: string[] }
          | null
          | undefined
        const groups = metadataAdmin?.groups || ['users']
        const organizations = Array.isArray(metadataAdmin?.organizations)
          ? (metadataAdmin!.organizations as string[])
          : []

        // Primary org = the native Kratos `organization_id` (root-level field
        // set via JSON Patch; the same field organization-user endpoints read).
        // Fall back to a traits.organization_id if a schema stores it there.
        const rootOrg = (identity as Record<string, unknown>).organization_id as
          | string
          | null
          | undefined
        const traitOrg = (identity.traits as Record<string, unknown> | undefined)
          ?.organization_id as string | null | undefined
        const primaryOrganization = rootOrg || traitOrg || null
        // `state` is a core list field (no include_credential needed); treat
        // only 'active' as active — inactive/undefined are not-active.
        const active = identity.state === 'active'
        const name = (identity.traits?.name as string | undefined) ?? null

        result.set(email, { groups, organizations, primaryOrganization, active, id: identity.id, name })
      }

      const next = response.nextPageToken
      if (!next || next === pageToken || response.identities.length === 0) break
      pageToken = next
    }

    // Update cache
    this.identityBindingsCache = {
      data: result,
      expiresAt: Date.now() + this.CACHE_TTL_MS,
    }

    return result
  }

  /**
   * Substring search over the in-memory identity map (email + name). Reuses the
   * light-walk cache (getAllIdentitiesWithBindings) — NO new PII store, no
   * per-request Kratos call, and it inherits that map's 5s TTL + mutation
   * invalidation so results stay current. Returns lightweight rows only
   * (no credentials / MFA). Case-insensitive; capped at `limit`.
   */
  async searchIdentities(
    q: string,
    limit = 50,
  ): Promise<Array<{ id: string; email: string; name: string | null; groups: string[]; organizationId: string | null; active: boolean }>> {
    const bindings = await this.getAllIdentitiesWithBindings()
    const low = q.trim().toLowerCase()
    const out: Array<{ id: string; email: string; name: string | null; groups: string[]; organizationId: string | null; active: boolean }> = []
    for (const [email, b] of bindings) {
      const match = !low || email.toLowerCase().includes(low) || (b.name?.toLowerCase().includes(low) ?? false)
      if (!match) continue
      out.push({ id: b.id, email, name: b.name, groups: b.groups, organizationId: b.primaryOrganization, active: b.active })
      if (out.length >= limit) break
    }
    return out
  }

  /**
   * Get all identities with their groups from metadata_admin.
   * Projection over getAllIdentitiesWithBindings (shares its cache + scan).
   *
   * @returns Map of email → groups array
   */
  async getAllIdentitiesWithGroups(): Promise<Map<string, string[]>> {
    const bindings = await this.getAllIdentitiesWithBindings()
    const result = new Map<string, string[]>()
    for (const [email, binding] of bindings) {
      result.set(email, binding.groups)
    }
    return result
  }

  /**
   * Invalidate the identity bindings cache (groups + organizations).
   * Call this after updating user groups/orgs to ensure OPAL gets fresh data.
   */
  invalidateGroupsCache(): void {
    this.identityBindingsCache = null
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
   * Look up an identity by email. Returns null if not found instead of
   * throwing, so callers can branch on absence without try/catch noise.
   */
  async findByEmail(email: string): Promise<KratosIdentity | null> {
    const response = await this.listIdentities(1, undefined, email)
    return response.identities[0] ?? null
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
   * List ALL identities in an organization, following Kratos's Link-header
   * pagination so members past the first page are never silently dropped
   * (finding J9 — the previous single-page fetch broke both the member list
   * and any search once the org grew past one page).
   *
   * `credentialsIdentifier` is Kratos's exact-match identifier filter (server
   * side) — not a substring. Both the org and the identifier filter are applied
   * by Kratos; we additionally re-filter by `organization_id` client-side as a
   * defence-in-depth guard in case Kratos ignores the org filter when an
   * identifier filter is also present.
   */
  async listIdentitiesByOrganization(
    organizationId: string,
    opts: { pageSize?: number; credentialsIdentifier?: string } = {}
  ): Promise<ListIdentitiesResponse> {
    const { pageSize = 250, credentialsIdentifier } = opts
    const collected: KratosIdentity[] = []
    const seenTokens = new Set<string>()
    let pageToken: string | undefined

    for (let page = 0; page < 1000; page++) {
      const response = await this.listIdentities(
        pageSize,
        pageToken,
        credentialsIdentifier,
        undefined,
        organizationId
      )

      for (const identity of response.identities) {
        const org = (identity as Record<string, unknown>).organization_id
        if (org === organizationId) collected.push(identity)
      }

      const next = response.nextPageToken
      // Terminate on end-of-list, empty page, or ANY previously-seen token (a
      // cycling A→B→A token sequence, not just an immediate repeat).
      if (!next || response.identities.length === 0 || seenTokens.has(next)) break
      seenTokens.add(next)
      pageToken = next
    }

    return { identities: collected, nextPageToken: undefined }
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
        // Serialize each user's write under the SAME per-user lock as
        // userGroupsService.applyGroupUpdate so a group-deletion cleanup can't
        // interleave with a concurrent group edit on the same user. Re-read the
        // current groups inside the lock — the bulk snapshot above can be stale
        // by the time we reach this user, and writing the stale set would clobber
        // a change committed since. See audit finding #9 (adjacent write path).
        const updated = await withRedisLock(`user-groups:${email}`, async () => {
          const current = await this.getUserGroups(email)
          if (!current.includes(groupName)) return false
          const newGroups = current.filter((g) => g !== groupName)
          // Ensure user always has at least ['users'] group
          const finalGroups = newGroups.length > 0 ? newGroups : ['users']
          await this.updateUserGroups(email, finalGroups)
          return true
        })
        if (updated) updatedCount++
      }
    }

    return updatedCount
  }
}

export const kratosService = new KratosService()
