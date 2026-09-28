import { env } from '../config/index.js'
import { withRedisLock } from './redis-lock.js'
import { SwrCache, type ReadOptions } from '../cache/swr.js'
import { rolesByOrganisation } from './organisation-store/membership.js'
import {
  KratosIdentity,
  KratosIdentityCreate,
  KratosIdentityUpdate,
} from '../schemas/admin.schema.js'

/**
 * Custom error class for Kratos API errors
 */
/** Second factors that lift a session to aal2. A passkey is a first factor and is not one of them. */
export const MFA_METHODS = ['totp', 'webauthn', 'lookup_secret'] as const
export type MfaMethod = (typeof MFA_METHODS)[number]

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
  /** metadata_admin.organization_roles: roles held in an organisation beyond plain membership. */
  organizationRoles: Record<string, string[]>
}

/**
 * The Kratos reads worth caching (src/cache/swr.ts), shared by every replica through Redis. Each holds
 * raw upstream data keyed by what it is about — never credentials: identities are cached as Kratos
 * returns them WITHOUT include_credential, and second factors only as the list of enrolled methods.
 *
 * Every write this service makes drops the entries it affects (see invalidate* below), Kratos
 * self-service flows do through the webhook, and the fresh windows bound changes made behind jinbe.
 */
const MINUTE = 60_000
const directoryCache = new SwrCache<Map<string, IdentityBinding>>({
  namespace: 'kratos.directory',
  freshMs: env.CACHE_DIRECTORY_FRESH_MS ?? 15_000,
  staleMs: 10 * MINUTE,
  encode: (m) => [...m],
  decode: (raw) => new Map(raw as Array<[string, IdentityBinding]>),
  l1Max: 1,
})
const identityCache = new SwrCache<KratosIdentity>({ namespace: 'kratos.identity', freshMs: 30_000, staleMs: 5 * MINUTE, l1Max: 5_000 })
const mfaCache = new SwrCache<MfaMethod[]>({ namespace: 'kratos.mfa', freshMs: MINUTE, staleMs: 10 * MINUTE, l1Max: 20_000 })
const orgMembersCache = new SwrCache<KratosIdentity[]>({ namespace: 'kratos.org', freshMs: 15_000, staleMs: 5 * MINUTE, l1Max: 200 })

/** What the identity list endpoint accepts per request for an `ids` filter. */
const IDS_PER_REQUEST = 100

/**
 * Kratos Admin API Service
 * Manages user identities via Ory Kratos Admin API
 */
export class KratosService {
  private adminUrl: string

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
   * Identities whose login identifier (email) STARTS WITH `prefix`, answered by Kratos's own index
   * (`preview_credentials_identifier_similar`, a `LIKE 'prefix%'` in v26.2) — one bounded query, never
   * a directory walk. Second-factor credentials are included so a caller can show 2FA without a call
   * per hit. Kratos marks the parameter experimental: a 400 from a build without it is returned as
   * `null`, so the caller can fall back rather than fail.
   */
  async listIdentitiesByIdentifierPrefix(prefix: string, limit: number): Promise<KratosIdentity[] | null> {
    const params = new URLSearchParams({ page_size: String(limit), preview_credentials_identifier_similar: prefix })
    for (const m of MFA_METHODS) params.append('include_credential', m)
    const response = await this.fetchWithTimeout(`${this.adminUrl}/admin/identities?${params.toString()}`, {
      headers: { 'Content-Type': 'application/json' },
    })
    if (response.status === 400) return null
    if (!response.ok) {
      throw new KratosApiError(response.status, `Kratos API error: ${response.statusText}`)
    }
    return ((await response.json()) as KratosIdentity[]).slice(0, limit)
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
    return (await this.mfaMethodsOf(id)).length > 0
  }

  /** The second factors this identity has enrolled (see mfaMethods). */
  async mfaMethodsOf(id: string): Promise<MfaMethod[]> {
    return this.mfaMethods((await this.getIdentityWithSecondFactors(id)).credentials)
  }

  /** The identity with its second-factor credentials' configs, which Kratos hides unless asked. */
  async getIdentityWithSecondFactors(id: string): Promise<KratosIdentity> {
    const params = new URLSearchParams()
    for (const m of MFA_METHODS) params.append('include_credential', m)
    return this.request<KratosIdentity>(`/admin/identities/${id}?${params.toString()}`)
  }

  /**
   * Removes one second factor: `DELETE /admin/identities/{id}/credentials/{type}`. For `webauthn`
   * Kratos drops the security keys and KEEPS the passwordless ones (passkeys); it refuses passkey
   * and first-factor deletions of its own. 404 when the identity has no credential of that type.
   */
  async deleteSecondFactor(id: string, type: MfaMethod): Promise<void> {
    await this.request<void>(`/admin/identities/${id}/credentials/${type}`, { method: 'DELETE' })
    this.invalidateSecondFactors(id)
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
   *   webauthn:      config.credentials[]       (registered security keys; a lone user_handle
   *                                              doesn't count, nor does a passwordless key — a
   *                                              passkey is a first factor)
   *   lookup_secret: config.recovery_codes[]    (generated codes)
   *
   * Requires the identity to have been fetched with include_credential for
   * these types; otherwise credentials is hidden and this returns false.
   */
  mfaFromCredentials(credentials: unknown): boolean {
    return this.mfaMethods(credentials).length > 0
  }

  /** Which second factors are really enrolled, by the artefacts described above. */
  mfaMethods(credentials: unknown): MfaMethod[] {
    const creds = (credentials || {}) as Record<
      string,
      { config?: Record<string, unknown> } | undefined
    >
    const totpReg = !!creds.totp?.config?.totp_url
    const webauthnKeys = (creds.webauthn?.config as any)?.credentials
    const webauthnReg = Array.isArray(webauthnKeys) &&
      webauthnKeys.some((k: { is_passwordless?: boolean }) => !k?.is_passwordless)
    const lookupReg = Array.isArray((creds.lookup_secret?.config as any)?.recovery_codes) &&
      ((creds.lookup_secret?.config as any).recovery_codes.length > 0)
    return MFA_METHODS.filter((m) => ({ totp: totpReg, webauthn: webauthnReg, lookup_secret: lookupReg })[m])
  }

  /**
   * Create new identity
   */
  async createIdentity(data: KratosIdentityCreate): Promise<KratosIdentity> {
    const created = await this.request<KratosIdentity>('/admin/identities', {
      method: 'POST',
      body: JSON.stringify(data),
    })
    this.invalidateGroupsCache()
    return created
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

    const updated = await this.request<KratosIdentity>(`/admin/identities/${id}`, {
      method: 'PUT',
      body: JSON.stringify(updatedData),
    })
    this.invalidateIdentity(id)
    return updated
  }

  /**
   * Patch identity via JSON Patch (RFC 6902)
   * Required for fields like organization_id that Kratos ignores on PUT
   */
  async patchIdentity(
    id: string,
    patches: Array<{ op: string; path: string; value: unknown }>
  ): Promise<KratosIdentity> {
    const patched = await this.request<KratosIdentity>(`/admin/identities/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(patches),
    })
    this.invalidateIdentity(id)
    return patched
  }

  /**
   * Delete identity by ID
   */
  async deleteIdentity(id: string): Promise<void> {
    await this.request<void>(`/admin/identities/${id}`, {
      method: 'DELETE',
    })
    this.invalidateIdentity(id)
    this.invalidateSecondFactors(id)
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
   * Best-effort extend a session's lifetime via Kratos admin
   * PATCH /admin/sessions/{id}/extend. Idempotent: Kratos only actually pushes
   * the expiry out once the session is past session.earliest_possible_extend,
   * so calling it on every whoami is safe (throttled server-side). Callers use
   * this fire-and-forget — a failure must never break the caller (see whoami).
   */
  async extendSession(sessionId: string): Promise<void> {
    await this.request<void>(`/admin/sessions/${sessionId}/extend`, { method: 'PATCH' })
  }

  /**
   * Revoke all sessions for an identity
   */
  async revokeAllIdentitySessions(identityId: string): Promise<void> {
    await this.request<void>(`/admin/identities/${identityId}/sessions`, { method: 'DELETE' })
  }

  /**
   * Get all identities with their full RBAC binding (groups + organizations +
   * primary organization) from a SINGLE paginated directory scan. Served from
   * the shared cache (kratos.directory): one walk per fresh window for the
   * whole cluster, stale-while-revalidate after it, dropped on every identity
   * write. A caller feeding authorization (the OPAL bindings) passes
   * `maxAgeMs` and never gets an older snapshot than that.
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
  async getAllIdentitiesWithBindings(opts: ReadOptions = {}): Promise<Map<string, IdentityBinding>> {
    return directoryCache.get('all', () => this.walkDirectory(), opts)
  }

  private async walkDirectory(): Promise<Map<string, IdentityBinding>> {
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
        const organizationRoles = rolesByOrganisation((metadataAdmin as Record<string, unknown> | null | undefined)?.organization_roles)

        result.set(email, { groups, organizations, primaryOrganization, active, id: identity.id, name, organizationRoles })
      }

      const next = response.nextPageToken
      if (!next || next === pageToken || response.identities.length === 0) break
      pageToken = next
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
    void directoryCache.invalidate()
    void orgMembersCache.invalidate()
  }

  /** One identity changed: its cached copy, and every listing it appears in. */
  invalidateIdentity(id: string): void {
    void identityCache.invalidate(id)
    this.invalidateGroupsCache()
  }

  /** One identity's second factors changed (enrolled, removed, reset). */
  invalidateSecondFactors(id: string): void {
    void mfaCache.invalidate(id)
  }

  /**
   * An identity by id, from the shared cache. For READ-ONLY views: anything that reads to write back
   * (updateIdentity's merge, a guard comparing before/after) calls getIdentity, which always asks.
   * Carries no credentials.
   */
  async getIdentityCached(id: string): Promise<KratosIdentity> {
    return identityCache.get(id, () => this.getIdentity(id))
  }

  /**
   * Many identities by id in one Kratos call per 100 (the `ids` filter), through the same cache.
   * Ids that do not exist are absent from the result.
   */
  async getIdentitiesByIds(ids: readonly string[]): Promise<Map<string, KratosIdentity>> {
    return identityCache.getMany(ids, async (missing) => {
      const out = new Map<string, KratosIdentity>()
      for (const identity of await this.listIdentitiesByIds(missing)) out.set(identity.id, identity)
      return out
    })
  }

  /**
   * The second factors enrolled by each of these identities, for DISPLAY (list columns, counts): one
   * Kratos call per 100 identities, cached a minute. The gates that decide on a second factor (group
   * grants, the enforcement check) call hasMFA / mfaMethodsOf, which always ask Kratos.
   */
  async mfaByIds(ids: readonly string[]): Promise<Map<string, MfaMethod[]>> {
    return mfaCache.getMany(ids, async (missing) => {
      const out = new Map<string, MfaMethod[]>()
      for (const identity of await this.listIdentitiesByIds(missing, [...MFA_METHODS])) {
        out.set(identity.id, this.mfaMethods(identity.credentials))
      }
      return out
    })
  }

  /**
   * `GET /admin/identities?ids=…` in chunks. Anything the filter did not return is fetched one by one,
   * so an older Kratos that ignores `ids` answers correctly, only slower.
   */
  private async listIdentitiesByIds(
    ids: readonly string[],
    includeCredential: Array<'totp' | 'webauthn' | 'lookup_secret'> = [],
  ): Promise<KratosIdentity[]> {
    const wanted = new Set(ids)
    const found = new Map<string, KratosIdentity>()
    const unique = [...wanted]
    for (let i = 0; i < unique.length; i += IDS_PER_REQUEST) {
      const chunk = unique.slice(i, i + IDS_PER_REQUEST)
      const params = new URLSearchParams({ page_size: String(chunk.length) })
      for (const id of chunk) params.append('ids', id)
      for (const c of includeCredential) params.append('include_credential', c)
      const page = await this.request<KratosIdentity[]>(`/admin/identities?${params.toString()}`)
      for (const identity of page ?? []) if (wanted.has(identity.id)) found.set(identity.id, identity)
    }
    for (const id of unique) {
      if (found.has(id)) continue
      const params = new URLSearchParams()
      for (const c of includeCredential) params.append('include_credential', c)
      const qs = params.toString()
      try {
        found.set(id, await this.request<KratosIdentity>(`/admin/identities/${id}${qs ? `?${qs}` : ''}`))
      } catch (err) {
        if ((err as { statusCode?: number }).statusCode !== 404) throw err
      }
    }
    return [...found.values()]
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

    // Only metadata_admin.groups is written, under the identity's lock and from a fresh read: a PUT
    // of the whole metadata from this (older) copy used to put back whatever organisations it held,
    // undoing a membership change made in between. Invalidates the cache so OPAL gets fresh data.
    return this.updateAdminState(identity.id, (state) => ({
      ...state,
      metadataAdmin: { ...state.metadataAdmin, groups },
    }))
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
   * listIdentitiesByOrganization through the shared cache (kratos.org), keyed by the organisation and
   * the identifier filter — the raw member list of THAT organisation, whoever asks. Who may ask is the
   * route guard's business and runs before this; nothing here is shaped by the caller. For display.
   */
  async listIdentitiesByOrganizationCached(
    organizationId: string,
    opts: { pageSize?: number; credentialsIdentifier?: string } = {}
  ): Promise<KratosIdentity[]> {
    const key = `${organizationId}\u0000${opts.credentialsIdentifier ?? ''}`
    return orgMembersCache.get(key, async () => (await this.listIdentitiesByOrganization(organizationId, opts)).identities)
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

  /**
   * Change what an administrator holds on an identity (its primary organisation and metadata_admin)
   * without losing somebody else's change.
   *
   * Kratos has no etag and its JSON Patch refuses `test`, so there is no compare-and-set to lean on.
   * Every writer in this service takes the identity's lock, reads it fresh inside the lock, and
   * sends ONE patch naming only what changed — one Kratos update, so the primary organisation and
   * the list move together, and a key nobody touched is never written from a stale copy.
   */
  async updateAdminState(id: string, change: (state: AdminState) => AdminState): Promise<KratosIdentity> {
    return withRedisLock(`identity:${id}`, async () => {
      const identity = await this.getIdentity(id)
      const raw = identity.metadata_admin
      const metadataAdmin = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : null
      const organizationId = ((identity as Record<string, unknown>).organization_id as string | null | undefined) ?? null
      const before: AdminState = { organizationId, metadataAdmin: structuredClone(metadataAdmin ?? {}) }
      const after = change(structuredClone(before))

      const patches: Array<{ op: string; path: string; value?: unknown }> = []
      if (after.organizationId !== before.organizationId) {
        patches.push({ op: 'replace', path: '/organization_id', value: after.organizationId })
      }
      if (!metadataAdmin) {
        if (Object.keys(after.metadataAdmin).length > 0) patches.push({ op: 'add', path: '/metadata_admin', value: after.metadataAdmin })
      } else {
        for (const key of new Set([...Object.keys(before.metadataAdmin), ...Object.keys(after.metadataAdmin)])) {
          const path = `/metadata_admin/${key.replace(/~/g, '~0').replace(/\//g, '~1')}`
          if (!(key in after.metadataAdmin)) patches.push({ op: 'remove', path })
          else if (JSON.stringify(before.metadataAdmin[key]) !== JSON.stringify(after.metadataAdmin[key])) {
            patches.push({ op: 'add', path, value: after.metadataAdmin[key] })
          }
        }
      }
      if (patches.length === 0) return identity

      // patchIdentity drops kratos.identity for this id, kratos.directory and kratos.org, on every replica.
      return this.patchIdentity(id, patches as Array<{ op: string; path: string; value: unknown }>)
    })
  }
}

/** What updateAdminState reads and writes: the primary organisation and metadata_admin. */
export interface AdminState {
  organizationId: string | null
  metadataAdmin: Record<string, unknown>
}

export const kratosService = new KratosService()
