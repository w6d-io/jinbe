import { env } from '../config/index.js'
import { hydraService, HydraApiError, type HydraOAuth2Client } from './hydra.service.js'
import { PERSONAL_KEY_PREFIX } from './delegated-token.service.js'
import { apiKeyService, ApiKeyError, expiryFrom, isPersonal, toView } from './api-key.service.js'
import { getApiKeyPolicy } from './api-key-policy.js'
import { isSuperAdmin, memberOrgs } from '../authz/opa.js'
import { kratosService } from './kratos.service.js'
import { personalScopeCatalog, type PersonalScopeEntry } from './platform-scopes.js'
import { isGrantableScope } from './authorization-resolution.js'
import { recordApiKeyUse } from '../audit/record.js'
import { forgetApiKeyUse, touchApiKeyUse } from './api-key-last-used.js'
import { mcpGate, orgAllowed, type McpSettings } from '../mcp/settings.js'
import type { ApiKeySecretView, ApiKeyView, PersonalKeyCreateBody } from '../schemas/api-key.schema.js'

/**
 * Personal API keys — a user's own key, acting AS that user in ONE organization (MCP groundwork,
 * behind DELEGATED_TOKENS_ENABLED).
 *
 * A Hydra client_credentials client with `owner = user:<id>` and metadata
 * `{kind: personal, subject, organization_id, expires_at}`; never listed with the org's machine keys.
 * Its token is introspected by jinbe's delegated path, which re-reads that metadata, so:
 *   - it never holds more than its user: scopes ⊆ what they hold in that org at creation — the org
 *     keys' site catalog plus jinbe's own permissions, for the MCP tools (platform-scopes.ts) — and
 *     every call still asks what the user holds now;
 *   - it always expires: 30 days at most (owner decision) — or less, when the administrator set a
 *     shorter maximum (mcp/settings.ts) — and is refused past `expires_at`;
 *   - the administrator may turn MCP off or limit it to some orgs: the keys stay stored, unusable;
 *   - the org may forbid personal keys, which stops the keys already issued too.
 * Creating one is a browser action: the delegation gate refuses /api/me/api-keys to delegated callers.
 */

export type PersonalKeyView = ApiKeyView & { kind: 'personal' }

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

const view = (client: HydraOAuth2Client): PersonalKeyView => ({ ...toView(client), kind: 'personal' })

/** MCP on (mcp/settings.ts) and `org` in its scope — the settings, or ApiKeyError 404/403 as the key routes answer. */
async function assertMcpFor(org: string): Promise<McpSettings> {
  const gate = await mcpGate()
  if (gate.off === 'unavailable') throw new ApiKeyError(503, 'The AI assistant settings cannot be read right now')
  if (!gate.on) throw new ApiKeyError(404, 'Personal API keys are turned off by an administrator.', { reason: 'mcp_disabled' })
  if (!orgAllowed(gate.settings, org)) {
    throw new ApiKeyError(403, 'AI assistants are not enabled for this organization', { reason: 'mcp_org_not_allowed' })
  }
  return gate.settings
}

async function assertMember(email: string, org: string): Promise<void> {
  const member = (await isSuperAdmin(email)) || (await memberOrgs(email)).includes(org)
  if (!member) throw new ApiKeyError(403, 'You are not a member of that organization')
}

export class PersonalKeyService {
  /**
   * The scopes the caller may give a personal key in `org`: that org's machine-key catalog plus the
   * jinbe permissions the MCP tools use, computed from what THEY hold. A member only (or
   * super_admin): 403 otherwise.
   */
  async scopes(caller: { email: string }, org: string): Promise<PersonalScopeEntry[]> {
    await assertMember(caller.email, org)
    await assertMcpFor(org)
    return personalScopeCatalog(org, caller.email)
  }

  async create(caller: { id: string; email: string }, body: PersonalKeyCreateBody): Promise<PersonalKeySecretView> {
    const org = body.organization_id
    await assertMember(caller.email, org)
    const settings = await assertMcpFor(org)
    const days = body.expires_in_days ?? settings.personalKeys.maxDays
    if (days > settings.personalKeys.maxDays) {
      throw new ApiKeyError(400, `A personal key may live at most ${settings.personalKeys.maxDays} days`, { reason: 'expiry_too_long', max_days: settings.personalKeys.maxDays })
    }
    if ((await getApiKeyPolicy(org)).personal_keys !== 'allowed') {
      throw new ApiKeyError(403, 'This organization does not allow personal API keys', { reason: 'personal_keys_forbidden' })
    }
    const scopes = [...new Set(body.scopes)]
    await apiKeyService.validateScopes(org, caller.email, scopes, personalScopeCatalog)

    const client = await hydraService.createClient({
      label: body.label,
      // `mcp` rides along so auth-mcp accepts the key's tokens; it is not a permission.
      scopes: [...scopes, MCP_SCOPE],
      organizationId: org,
      createdBy: caller.id,
      expiresAt: expiryFrom(days),
      personal: { subject: caller.id },
      // The delegated path only takes a token for its own audience.
      ...(env.DELEGATED_TOKEN_AUDIENCE ? { audience: [env.DELEGATED_TOKEN_AUDIENCE] } : {}),
    })
    const secret = client.client_secret ?? ''
    return { ...view(client), created_by_email: caller.email, client_secret: secret, key: `${PERSONAL_KEY_PREFIX}${client.client_id}.${secret}` }
  }

  /**
   * A personal key's secret → a short-lived token (auth-mcp's JinbeKeyExchanger). The token carries the
   * key's stored scopes that its holder STILL holds in the key's org (site and jinbe permissions,
   * the same catalog as at creation) — re-read now, so a demotion narrows the next token — plus
   * `mcp`. Refused when the key is unknown, not personal, expired, its
   * org forbids personal keys, its holder is gone or disabled, or Hydra refuses the secret.
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
    const org = meta.organization_id
    const expiresAt = typeof meta.expires_at === 'string' ? Date.parse(meta.expires_at) : NaN
    if (!isPersonal(client) || !subject || typeof org !== 'string' || !org) throw new PersonalKeyRefused('not_a_personal_key')
    if (!(expiresAt > now)) throw new PersonalKeyRefused('key_expired')
    const gate = await mcpGate()
    if (!gate.on) throw new PersonalKeyRefused(gate.off === 'unavailable' ? 'mcp_settings_unavailable' : 'mcp_disabled')
    if (!orgAllowed(gate.settings, org)) throw new PersonalKeyRefused('mcp_org_not_allowed')
    if ((await getApiKeyPolicy(org)).personal_keys !== 'allowed') throw new PersonalKeyRefused('personal_keys_forbidden')

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

    const held = new Set((await personalScopeCatalog(org, email)).map((e) => e.scope))
    const stored = (client.scope ?? '').split(' ').filter(Boolean)
    const scopes = [...stored.filter((s) => isGrantableScope(s) && held.has(s)), ...(stored.includes(MCP_SCOPE) ? [MCP_SCOPE] : [])]

    let token: { access_token: string; expires_in: number }
    try {
      token = await hydraService.clientCredentialsToken(clientId, secret, scopes, env.DELEGATED_TOKEN_AUDIENCE)
    } catch (err) {
      if (err instanceof HydraApiError && (err.statusCode === 400 || err.statusCode === 401)) throw new PersonalKeyRefused('key_refused')
      throw err
    }
    void recordApiKeyUse(clientId, org)
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
export type PersonalKeySecretView = ApiKeySecretView & { kind: 'personal'; key: string }

export const personalKeyService = new PersonalKeyService()
