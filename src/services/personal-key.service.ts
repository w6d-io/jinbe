import { env } from '../config/index.js'
import { hydraService, HydraApiError, type HydraOAuth2Client } from './hydra.service.js'
import { PERSONAL_KEY_PREFIX, allPermissionsKey } from './delegated-token.service.js'
import { ApiKeyError, expiryFrom, isPersonal, toView } from './api-key.service.js'
import { rights } from '../authz/opa.js'
import { kratosService } from './kratos.service.js'
import { personalScopeCatalog, platformScopes, type PersonalScopeEntry } from './platform-scopes.js'
import { isGrantableScope } from './authorization-resolution.js'
import { recordApiKeyUse } from '../audit/record.js'
import { forgetApiKeyUse, touchApiKeyUse } from './api-key-last-used.js'
import { groupAllowed, mcpGate, type McpSettings } from '../mcp/settings.js'
import type { ApiKeySecretView, ApiKeyView, PersonalKeyCreateBody } from '../schemas/api-key.schema.js'

/**
 * Personal API keys — a user's own key for an MCP client, acting AS that user (behind
 * DELEGATED_TOKENS_ENABLED and the administrator's switch).
 *
 * Staff rights come from groups, and a personal key INHERITS them. It is bound to no organization
 * (orgs secure sites; their machine keys are api-key.service.ts):
 *   - by default it carries "all my permissions" — whatever its holder holds at each call; or a
 *     subset chosen at creation among what they hold (platform-scopes.ts: concrete permissions, never
 *     `*`). Either way every call recomputes what the holder STILL holds (delegated-token.service.ts)
 *     and the route gates ask their current rights again: a removed group stops the key at once;
 *   - the always-refused delegated routes stay refused (middleware/delegation-gate.ts);
 *   - it always expires: 30 days at most (owner decision) — or less, when the administrator set a
 *     shorter maximum (mcp/settings.ts) — and is refused past `expires_at`;
 *   - the administrator may turn MCP off or limit it to some groups: the keys stay stored, unusable.
 *
 * A Hydra client_credentials client with `owner = user:<id>` and metadata
 * `{kind: personal, subject, scope_mode: all|selected, expires_at}`; never listed with an org's keys.
 * Creating one is a browser action: the delegation gate refuses /api/me/api-keys to delegated callers.
 */

export type PersonalKeyView = Omit<ApiKeyView, 'organization_id'> & {
  kind: 'personal'
  /** Keys made before personal keys stopped being org-bound still name one; it no longer means anything. */
  organization_id: string | null
  /** True: the key carries all its holder's permissions, and `scopes` is empty. */
  all_permissions: boolean
}

/** The baseline scope auth-mcp requires on every token (it is not a permission and opens nothing here). */
export const MCP_SCOPE = 'mcp'

/** A key exchange refused for a reason the caller may learn (the answer is 401 either way). */
export class PersonalKeyRefused extends Error {
  constructor(public readonly reason: string) {
    super(reason)
    this.name = 'PersonalKeyRefused'
  }
}

const owner = (subject: string) => `user:${subject}`

function subjectOf(client: HydraOAuth2Client): string | undefined {
  const s = (client.metadata as Record<string, unknown> | undefined)?.subject
  return typeof s === 'string' ? s : undefined
}

const view = (client: HydraOAuth2Client): PersonalKeyView => {
  const meta = (client.metadata ?? {}) as Record<string, unknown>
  const all = allPermissionsKey(meta)
  return {
    ...toView(client),
    kind: 'personal',
    organization_id: typeof meta.organization_id === 'string' ? meta.organization_id : null,
    scopes: all ? [] : toView(client).scopes.filter(isGrantableScope),
    all_permissions: all,
  }
}

/** MCP on (mcp/settings.ts) — the settings, or ApiKeyError 404/503 as the key routes answer. */
async function assertMcpOn(): Promise<McpSettings> {
  const gate = await mcpGate()
  if (gate.off === 'unavailable') throw new ApiKeyError(503, 'The AI assistant settings cannot be read right now')
  if (!gate.on) throw new ApiKeyError(404, 'Personal API keys are turned off by an administrator.', { reason: 'mcp_disabled' })
  return gate.settings
}

/** The caller's groups may use MCP (allowedGroups): 403 otherwise. */
async function assertGroupAllowed(settings: McpSettings, email: string): Promise<void> {
  if (!groupAllowed(settings, (await rights(email)).groups)) {
    throw new ApiKeyError(403, 'AI assistants are not enabled for your groups', { reason: 'mcp_group_not_allowed' })
  }
}

export class PersonalKeyService {
  /**
   * What the caller may narrow a personal key to: the jinbe permissions they hold, concrete, grouped
   * by resource. Throws AuthzUnavailableError when OPA cannot be asked.
   */
  async scopes(caller: { email: string }): Promise<PersonalScopeEntry[]> {
    const settings = await assertMcpOn()
    await assertGroupAllowed(settings, caller.email)
    return personalScopeCatalog(caller.email)
  }

  /** `scopes` absent: "all my permissions". Present: a non-empty subset of what the caller holds. */
  async create(caller: { id: string; email: string }, body: PersonalKeyCreateBody): Promise<PersonalKeySecretView> {
    const settings = await assertMcpOn()
    await assertGroupAllowed(settings, caller.email)
    const days = body.expires_in_days ?? settings.personalKeys.maxDays
    if (days > settings.personalKeys.maxDays) {
      throw new ApiKeyError(400, `A personal key may live at most ${settings.personalKeys.maxDays} days`, { reason: 'expiry_too_long', max_days: settings.personalKeys.maxDays })
    }
    const all = body.scopes === undefined
    const scopes = all ? [] : [...new Set(body.scopes)]
    if (!all) {
      const allowed = new Set(await platformScopes(caller.email))
      const invalid = scopes.filter((s) => !isGrantableScope(s) || !allowed.has(s))
      if (invalid.length > 0) {
        throw new ApiKeyError(400, 'One or more requested scopes are not allowed', { invalid_scopes: invalid, allowed_scopes: [...allowed] })
      }
    }

    const client = await hydraService.createClient({
      label: body.label,
      // `mcp` rides along so auth-mcp accepts the key's tokens; it is not a permission. An
      // "all my permissions" key registers no permission: jinbe computes them at each call.
      scopes: [...scopes, MCP_SCOPE],
      createdBy: caller.id,
      expiresAt: expiryFrom(days),
      personal: { subject: caller.id, allPermissions: all },
      // The delegated path only takes a token for its own audience.
      ...(env.DELEGATED_TOKEN_AUDIENCE ? { audience: [env.DELEGATED_TOKEN_AUDIENCE] } : {}),
    })
    const secret = client.client_secret ?? ''
    return { ...view(client), created_by_email: caller.email, client_secret: secret, key: `${PERSONAL_KEY_PREFIX}${client.client_id}.${secret}` }
  }

  /**
   * A personal key's secret → a short-lived token (auth-mcp's JinbeKeyExchanger). A narrowed key's
   * token carries its stored scopes that its holder STILL holds — re-read now — plus `mcp`; an "all my
   * permissions" key's carries `mcp` alone, its permissions being computed at each call. Refused when
   * the key is unknown, not personal, expired, its holder is gone, disabled or outside the groups
   * allowed MCP, or Hydra refuses the secret.
   */
  async exchange(clientId: string, secret: string, now: number = Date.now()): Promise<{ access_token: string; expires_in: number }> {
    if (!env.DELEGATED_TOKEN_AUDIENCE) throw new PersonalKeyRefused('delegated_audience_unset')
    let client: HydraOAuth2Client
    try {
      client = await hydraService.getClient(clientId)
    } catch (err) {
      if (err instanceof HydraApiError && err.statusCode === 404) throw new PersonalKeyRefused('unknown_key')
      throw err
    }
    const meta = (client.metadata ?? {}) as Record<string, unknown>
    const subject = subjectOf(client)
    const expiresAt = typeof meta.expires_at === 'string' ? Date.parse(meta.expires_at) : NaN
    if (!isPersonal(client) || !subject) throw new PersonalKeyRefused('not_a_personal_key')
    if (!(expiresAt > now)) throw new PersonalKeyRefused('key_expired')
    const gate = await mcpGate()
    if (!gate.on) throw new PersonalKeyRefused(gate.off === 'unavailable' ? 'mcp_settings_unavailable' : 'mcp_disabled')

    let email: unknown
    try {
      const identity = await kratosService.getIdentity(subject)
      if (identity.state && identity.state !== 'active') throw new PersonalKeyRefused('subject_inactive')
      email = (identity.traits as Record<string, unknown> | undefined)?.email
    } catch (err) {
      if (err instanceof PersonalKeyRefused) throw err
      throw new PersonalKeyRefused('subject_unknown')
    }
    if (typeof email !== 'string' || !email) throw new PersonalKeyRefused('subject_unknown')
    if (!groupAllowed(gate.settings, (await rights(email)).groups)) throw new PersonalKeyRefused('mcp_group_not_allowed')

    const stored = (client.scope ?? '').split(' ').filter(Boolean)
    const held = allPermissionsKey(meta) ? new Set<string>() : new Set(await platformScopes(email))
    const scopes = [...stored.filter((s) => isGrantableScope(s) && held.has(s)), ...(stored.includes(MCP_SCOPE) ? [MCP_SCOPE] : [])]

    let token: { access_token: string; expires_in: number }
    try {
      token = await hydraService.clientCredentialsToken(clientId, secret, scopes, env.DELEGATED_TOKEN_AUDIENCE)
    } catch (err) {
      if (err instanceof HydraApiError && (err.statusCode === 400 || err.statusCode === 401)) throw new PersonalKeyRefused('key_refused')
      throw err
    }
    void recordApiKeyUse(clientId, typeof meta.organization_id === 'string' ? meta.organization_id : null)
    touchApiKeyUse(clientId)
    // Never outlive the key.
    return { access_token: token.access_token, expires_in: Math.max(1, Math.min(token.expires_in, Math.floor((expiresAt - now) / 1000))) }
  }

  async list(subject: string): Promise<PersonalKeyView[]> {
    const clients = await hydraService.listClientsByOwner(owner(subject))
    return clients.filter((c) => isPersonal(c) && subjectOf(c) === subject).map(view)
  }

  /** Revoke one of the caller's own keys (404 for anybody else's, or an org key). */
  async revoke(subject: string, clientId: string): Promise<PersonalKeyView> {
    let client: HydraOAuth2Client
    try {
      client = await hydraService.getClient(clientId)
    } catch (err) {
      if (err instanceof HydraApiError && err.statusCode === 404) throw new ApiKeyError(404, 'API key not found')
      throw err
    }
    if (!isPersonal(client) || subjectOf(client) !== subject) throw new ApiKeyError(404, 'API key not found')
    await hydraService.deleteClient(clientId)
    forgetApiKeyUse(clientId)
    return view(client)
  }
}

/** Returned once: the secret, and the key as auth-mcp takes it (`stk_mcp_<client_id>.<secret>`). */
export type PersonalKeySecretView = PersonalKeyView & Pick<ApiKeySecretView, 'client_secret'> & { key: string }

export const personalKeyService = new PersonalKeyService()
