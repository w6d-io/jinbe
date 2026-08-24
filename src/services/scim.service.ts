import { kratosService, KratosApiError } from './kratos.service.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'

/**
 * SCIM 2.0 service — Users only (spec phase 1).
 *
 * SCIM resources are VIEWS over the existing model (docs/specs/scim-provisioning.md §1):
 *   User            → Kratos identity (admin API)
 *   userName/emails → traits.email
 *   name            → traits.name (single string in this deployment's schema —
 *                     givenName/familyName are joined on write, split on read)
 *   active          → identity.state ('active' / 'inactive')
 *   groups          → metadata_admin.groups (readOnly through SCIM in phase 1)
 *   externalId      → metadata_admin.scim = { externalId, managed: true, idp, syncedAt }
 *
 * DELETE and PATCH active=false soft-deactivate (state 'inactive' + session
 * revocation). deleteIdentity is NEVER called — audit trail / grant provenance
 * reference the email (spec §4).
 */

export const SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User'
export const SCIM_LIST_RESPONSE_URN = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
export const SCIM_PATCH_OP_URN = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'

/** ServiceProviderConfig filter.maxResults — also caps unlimited list requests. */
export const SCIM_MAX_RESULTS = 200

/** Caller-facing SCIM failure — routes map it to an RFC 7644 error body. */
export class ScimError extends Error {
  constructor(
    public status: number,
    message: string,
    public scimType?: string
  ) {
    super(message)
    this.name = 'ScimError'
  }
}

export interface ScimName {
  givenName?: string
  familyName?: string
  formatted?: string
}

/** Inbound SCIM User payload (POST / PUT). Loosely typed — IdPs vary. */
export interface ScimUserInput {
  userName?: string
  externalId?: string
  name?: ScimName
  displayName?: string
  emails?: Array<{ value?: string; primary?: boolean; type?: string }>
  active?: boolean
}

export interface ScimPatchOperation {
  op: string
  path?: string
  value?: unknown
}

interface ScimMetadata {
  externalId: string | null
  managed: boolean
  idp: string
  syncedAt: string
}

/** Only `userName eq "x"` / `externalId eq "x"` are supported (spec §2). */
interface ParsedFilter {
  attribute: 'userName' | 'externalId'
  value: string
}

function metadataOf(identity: KratosIdentity): Record<string, unknown> {
  return (identity.metadata_admin || {}) as Record<string, unknown>
}

function scimMetaOf(identity: KratosIdentity): Partial<ScimMetadata> {
  const scim = metadataOf(identity).scim
  return (scim && typeof scim === 'object' ? scim : {}) as Partial<ScimMetadata>
}

/** Entra sends booleans as "True"/"False" strings in PATCH values. */
function coerceBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value
  if (typeof value === 'string') {
    const low = value.trim().toLowerCase()
    if (low === 'true') return true
    if (low === 'false') return false
  }
  return undefined
}

/** Join SCIM name parts into the single string trait this schema stores. */
function nameFromInput(body: ScimUserInput): string | undefined {
  const parts = [body.name?.givenName, body.name?.familyName].filter(Boolean)
  if (parts.length > 0) return parts.join(' ')
  return body.name?.formatted || body.displayName || undefined
}

function emailFromInput(body: ScimUserInput): string | undefined {
  const primary = body.emails?.find((e) => e.primary)?.value
  const raw = body.userName || primary || body.emails?.[0]?.value
  return raw ? String(raw).trim().toLowerCase() : undefined
}

export class ScimService {
  /** Kratos identity → RFC 7643 User resource. */
  toScimUser(identity: KratosIdentity): Record<string, unknown> {
    const email = identity.traits?.email as string
    const fullName = (identity.traits?.name as string | undefined) || undefined
    const scim = scimMetaOf(identity)
    const groups = (metadataOf(identity).groups as string[] | undefined) || ['users']

    let name: ScimName | undefined
    if (fullName) {
      const [givenName, ...rest] = fullName.split(' ')
      name = {
        formatted: fullName,
        givenName,
        ...(rest.length > 0 ? { familyName: rest.join(' ') } : {}),
      }
    }

    return {
      schemas: [SCIM_USER_SCHEMA],
      id: identity.id,
      ...(scim.externalId ? { externalId: scim.externalId } : {}),
      userName: email,
      ...(name ? { name } : {}),
      ...(fullName ? { displayName: fullName } : {}),
      emails: [{ value: email, primary: true }],
      active: identity.state === 'active',
      groups: groups.map((g) => ({ value: g, display: g, type: 'direct' })),
      meta: {
        resourceType: 'User',
        created: identity.created_at,
        lastModified: identity.updated_at,
        location: `/scim/v2/Users/${identity.id}`,
      },
    }
  }

  /**
   * Whitelist filter parser (no full RFC 7644 grammar): exactly
   * `userName eq "x"` or `externalId eq "x"`, attribute + operator
   * case-insensitive. Anything else → 501 per spec §2.
   */
  parseFilter(filter?: string): ParsedFilter | null {
    if (!filter || !filter.trim()) return null
    const match = /^\s*(userName|externalId)\s+eq\s+"([^"]*)"\s*$/i.exec(filter)
    if (!match) {
      throw new ScimError(
        501,
        `Unsupported filter: only 'userName eq "..."' and 'externalId eq "..."' are supported.`
      )
    }
    const attribute =
      match[1].toLowerCase() === 'username' ? 'userName' : 'externalId'
    return { attribute, value: match[2] }
  }

  /**
   * GET /Users — filter + 1-based startIndex / count pagination (RFC 7644
   * §3.4.2.4: startIndex < 1 → 1, count < 0 → 0).
   */
  async listUsers(opts: {
    filter?: string
    startIndex?: number
    count?: number
  }): Promise<{
    totalResults: number
    startIndex: number
    itemsPerPage: number
    resources: Array<Record<string, unknown>>
  }> {
    const parsed = this.parseFilter(opts.filter)
    const startIndex = Math.max(1, Math.trunc(opts.startIndex ?? 1))
    const count = Math.min(
      SCIM_MAX_RESULTS,
      Math.max(0, Math.trunc(opts.count ?? SCIM_MAX_RESULTS))
    )

    let matched: KratosIdentity[]
    if (parsed?.attribute === 'userName') {
      // Exact email lookup — Kratos's credentials_identifier filter, same key
      // as findByEmail. Case-insensitive: identifiers are stored lowercased.
      const identity = await kratosService.findByEmail(parsed.value.toLowerCase())
      matched = identity ? [identity] : []
    } else {
      const all = await this.listAllIdentities()
      matched = parsed
        ? all.filter((i) => scimMetaOf(i).externalId === parsed.value)
        : all
    }

    const page = matched.slice(startIndex - 1, startIndex - 1 + count)
    return {
      totalResults: matched.length,
      startIndex,
      itemsPerPage: page.length,
      resources: page.map((i) => this.toScimUser(i)),
    }
  }

  /** GET /Users/:id */
  async getUser(id: string): Promise<Record<string, unknown>> {
    return this.toScimUser(await this.getIdentityOr404(id))
  }

  /**
   * POST /Users — create the Kratos identity with default group ['users'] and
   * scim.managed marking. Existing email → 409 uniqueness (adoption then goes
   * through the IdP's GET + PATCH, spec §4).
   */
  async createUser(
    body: ScimUserInput,
    tokenId: string
  ): Promise<Record<string, unknown>> {
    const email = emailFromInput(body)
    if (!email) {
      throw new ScimError(400, 'userName (or a primary email) is required.', 'invalidValue')
    }
    const existing = await kratosService.findByEmail(email)
    if (existing) {
      throw new ScimError(409, `A user with userName '${email}' already exists.`, 'uniqueness')
    }

    const name = nameFromInput(body)
    const identity = await kratosService.createIdentity({
      schema_id: 'default',
      state: body.active === false ? 'inactive' : 'active',
      traits: { email, ...(name ? { name } : {}) },
      metadata_admin: {
        groups: ['users'],
        scim: this.scimMetadata(body.externalId ?? null, tokenId),
      },
    })
    kratosService.invalidateGroupsCache()
    return this.toScimUser(identity)
  }

  /** PUT /Users/:id — replace traits + active state; preserves groups. */
  async replaceUser(
    id: string,
    body: ScimUserInput,
    tokenId: string
  ): Promise<Record<string, unknown>> {
    const current = await this.getIdentityOr404(id)
    const email = emailFromInput(body) || (current.traits?.email as string)
    if (email !== current.traits?.email) {
      const other = await kratosService.findByEmail(email)
      if (other && other.id !== id) {
        throw new ScimError(409, `A user with userName '${email}' already exists.`, 'uniqueness')
      }
    }
    return this.applyIdentityUpdate(current, {
      email,
      name: nameFromInput(body),
      active: body.active !== false,
      externalId: body.externalId,
      tokenId,
    })
  }

  /**
   * PATCH /Users/:id — RFC 7644 PatchOp. Supported paths: active (minimum per
   * spec phase 1), userName / emails, name.*, displayName, externalId. Both
   * pathed ops and the no-path `value: { active: false, ... }` form (Entra
   * uses both). Unknown paths are ignored so an IdP pushing extra attributes
   * doesn't hard-fail provisioning.
   */
  async patchUser(
    id: string,
    patchBody: { Operations?: ScimPatchOperation[] },
    tokenId: string
  ): Promise<Record<string, unknown>> {
    const operations = patchBody?.Operations
    if (!Array.isArray(operations) || operations.length === 0) {
      throw new ScimError(400, 'PatchOp must contain a non-empty Operations array.', 'invalidSyntax')
    }

    const current = await this.getIdentityOr404(id)
    const changes: {
      email?: string
      name?: string
      active?: boolean
      externalId?: string | null
    } = {}
    // Track name parts so `name.givenName` + `name.familyName` compose.
    const currentName = (current.traits?.name as string | undefined) || ''
    const currentParts = currentName.split(' ')
    let givenName = currentParts[0]
    let familyName = currentParts.slice(1).join(' ')
    let nameTouched = false

    const applyAttribute = (path: string, value: unknown) => {
      const low = path.toLowerCase()
      if (low === 'active') {
        const active = coerceBoolean(value)
        if (active === undefined) {
          throw new ScimError(400, `Invalid value for 'active': ${String(value)}`, 'invalidValue')
        }
        changes.active = active
      } else if (low === 'username') {
        if (typeof value === 'string' && value.trim()) changes.email = value.trim().toLowerCase()
      } else if (low.startsWith('emails')) {
        if (typeof value === 'string' && value.trim()) changes.email = value.trim().toLowerCase()
      } else if (low === 'name.givenname') {
        givenName = typeof value === 'string' ? value : ''
        nameTouched = true
      } else if (low === 'name.familyname') {
        familyName = typeof value === 'string' ? value : ''
        nameTouched = true
      } else if (low === 'name.formatted' || low === 'displayname') {
        if (typeof value === 'string') changes.name = value
      } else if (low === 'name') {
        const v = (value || {}) as ScimName
        const joined = [v.givenName, v.familyName].filter(Boolean).join(' ') || v.formatted
        if (joined) changes.name = joined
      } else if (low === 'externalid') {
        changes.externalId = typeof value === 'string' ? value : null
      }
      // Unknown attribute → ignored (deliberate — see docblock).
    }

    for (const operation of operations) {
      const op = String(operation.op || '').toLowerCase()
      if (op !== 'add' && op !== 'replace' && op !== 'remove') {
        throw new ScimError(400, `Unsupported PATCH op: ${operation.op}`, 'invalidSyntax')
      }
      if (op === 'remove') {
        if (operation.path?.toLowerCase() === 'externalid') changes.externalId = null
        continue
      }
      if (operation.path) {
        applyAttribute(operation.path, operation.value)
      } else {
        // No path: value is an object of attribute → value (RFC 7644 §3.5.2.1).
        const value = operation.value
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
          throw new ScimError(400, 'PATCH operation without a path requires an object value.', 'invalidValue')
        }
        for (const [attr, v] of Object.entries(value as Record<string, unknown>)) {
          applyAttribute(attr, v)
        }
      }
    }

    if (nameTouched && changes.name === undefined) {
      changes.name = [givenName, familyName].filter(Boolean).join(' ')
    }
    if (changes.email && changes.email !== current.traits?.email) {
      const other = await kratosService.findByEmail(changes.email)
      if (other && other.id !== id) {
        throw new ScimError(409, `A user with userName '${changes.email}' already exists.`, 'uniqueness')
      }
    }

    return this.applyIdentityUpdate(current, {
      email: changes.email ?? (current.traits?.email as string),
      name: changes.name,
      active: changes.active ?? (current.state === 'active'),
      externalId:
        changes.externalId !== undefined
          ? changes.externalId ?? undefined
          : undefined,
      externalIdCleared: changes.externalId === null,
      tokenId,
    })
  }

  /**
   * DELETE /Users/:id — SOFT delete: state 'inactive' + revoke all sessions.
   * Never kratosService.deleteIdentity (spec §4).
   */
  async deactivateUser(id: string, tokenId: string): Promise<void> {
    const current = await this.getIdentityOr404(id)
    await this.applyIdentityUpdate(current, {
      email: current.traits?.email as string,
      active: false,
      tokenId,
    })
  }

  // ── internals ──────────────────────────────────────────────────────────────

  private scimMetadata(externalId: string | null, tokenId: string): ScimMetadata {
    return {
      externalId,
      managed: true,
      idp: tokenId,
      syncedAt: new Date().toISOString(),
    }
  }

  private async getIdentityOr404(id: string): Promise<KratosIdentity> {
    try {
      return await kratosService.getIdentity(id)
    } catch (err) {
      if (err instanceof KratosApiError && err.statusCode === 404) {
        throw new ScimError(404, `Resource ${id} not found.`)
      }
      throw err
    }
  }

  /**
   * Shared write path: updates traits/state, refreshes metadata_admin.scim
   * (adoption writes externalId + managed on first SCIM write, spec §4), and
   * revokes sessions on an active → inactive transition.
   */
  private async applyIdentityUpdate(
    current: KratosIdentity,
    update: {
      email: string
      name?: string
      active: boolean
      externalId?: string
      externalIdCleared?: boolean
      tokenId: string
    }
  ): Promise<Record<string, unknown>> {
    const previousScim = scimMetaOf(current)
    const externalId = update.externalIdCleared
      ? null
      : update.externalId ?? previousScim.externalId ?? null
    const metadataAdmin = {
      ...metadataOf(current),
      scim: this.scimMetadata(externalId, update.tokenId),
    }

    const identity = await kratosService.updateIdentity(current.id, {
      traits: {
        email: update.email,
        ...(update.name !== undefined ? { name: update.name } : {}),
      },
      state: update.active ? 'active' : 'inactive',
      metadata_admin: metadataAdmin,
    })
    kratosService.invalidateGroupsCache()

    if (!update.active && current.state === 'active') {
      // Best-effort: a session-revocation failure must not fail the deactivate
      // itself — the state flip already blocks new logins.
      await kratosService.revokeAllIdentitySessions(current.id).catch(() => {})
    }
    return this.toScimUser(identity)
  }

  /** Full directory walk (Link-header pagination, page cap mirrors kratos.service). */
  private async listAllIdentities(): Promise<KratosIdentity[]> {
    const collected: KratosIdentity[] = []
    let pageToken: string | undefined
    for (let page = 0; page < 1000; page++) {
      const response = await kratosService.listIdentities(500, pageToken)
      collected.push(...response.identities)
      const next = response.nextPageToken
      if (!next || next === pageToken || response.identities.length === 0) break
      pageToken = next
    }
    return collected
  }
}

export const scimService = new ScimService()
