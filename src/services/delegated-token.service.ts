import { createHash } from 'node:crypto'
import { env } from '../config/index.js'
import { hydraService, type HydraIntrospection } from './hydra.service.js'
import { kratosService } from './kratos.service.js'
import { isGrantableScope } from './authorization-resolution.js'
import { componentLogger } from '../telemetry/logger.js'
import { touchApiKeyUse } from './api-key-last-used.js'
import { groupAllowed, mcpGate, type McpSettings } from '../mcp/settings.js'
import { rights } from '../authz/opa.js'
import { platformScopes } from './platform-scopes.js'
import { broadcastInvalidation, ensureBus, onInvalidate } from '../cache/swr.js'
import { getStore } from '../cache/runtime.js'
import { hydraFlows } from './hydra-flows.service.js'
import { oauthStepUpUntil } from '../oauth/step-up-window.js'
import { oauthAudit } from '../oauth/audit.js'
import { laterProof, refreshedOAuthProof } from '../oauth/step-up-proof.js'

const log = () => componentLogger('delegated-token')

/**
 * A USER acting through a client, proven by an opaque Hydra access token (MCP prerequisite).
 *
 * Two ways in, one shape out:
 *   - an OAuth token (authorization code, browser sign-in — src/oauth/): `sub` is the user; the client
 *     must be an MCP registration (`metadata.kind: mcp_oauth`) bound to that user, and the consent's
 *     stamp (`ext`: scope mode, consent-time second factor, protected actions, absolute end) is read
 *     like a personal key's metadata — past `grant_expires_at` the token is refused and the sign-in
 *     revoked; `ext.org`, when present, is carried along for information only;
 *   - a personal key (client_credentials, `owner = user:<id>`): `sub` is the client, and the user is
 *     read from the client's own metadata, re-read on every introspection — so revoking the key or
 *     letting it expire stops it within the cache window.
 *
 * Bound to no organization: a personal key or a sign-in inherits its holder. Its scopes are recomputed
 * on EVERY call from what the holder holds now (platform-scopes.ts) — all of it for "all my
 * permissions", the stored (granted) subset still held otherwise — and the holder's groups must still be allowed MCP
 * (mcp/settings.ts allowedGroups). A removed group narrows the very next call.
 *
 * An org machine key is NOT a user and never comes out of here.
 *
 * The token narrows, it never widens: jinbe still asks what the USER may do, then requires a scope
 * to cover it (middleware/delegation-gate.ts). A token asserts no second factor, so it can never pass
 * a step-up.
 */
export interface DelegatedPrincipal {
  subject: string
  email: string
  name: string
  clientId: string
  /**
   * Grantable scopes only (resource:verb) — `mcp`, `offline_access` and wildcards are dropped. For a
   * personal key: what its holder holds NOW (all of it, or the stored subset still held).
   */
  scopes: string[]
  /** An OAuth token's consent org, when it names one — informational, never an authorization. */
  org?: string
  kind: 'oauth' | 'personal'
  /** Personal keys: the key carries all its holder's permissions (no stored subset). */
  allPermissions?: boolean
  /** ms since epoch. */
  expiresAt: number
  /** The effective scope string (with `mcp`, `offline_access` as granted) — for /api/mcp/token-info. */
  tokenScope: string
  /** The introspected audience. */
  aud: string[]
  /** Personal keys: the key's own expiry (ms since epoch). */
  keyExpiresAt?: number
  /** Personal key: when its creator proved a second factor (ISO), and whether step-up actions are allowed. */
  keyStepUpAt?: string
  keyStepUpActions?: boolean
  /** OAuth: 'all' follows the holder's rights at each call; 'chosen' is the granted subset still held. */
  scopeMode?: 'all' | 'chosen'
  /** OAuth: the consent-time second factor (ISO) and whether protected actions were allowed at consent. */
  stepUpAt?: string
  stepUpActions?: boolean
  /** OAuth: until when protected actions are allowed (ISO), from the settings' window — absent: none. */
  stepUpUntil?: string
  /** OAuth: the sign-in's absolute end (ms since epoch). */
  grantExpiresAt?: number
  /** OAuth: the registration's (unverified) name. */
  clientName?: string
}

export type DelegatedResult = { principal: DelegatedPrincipal } | { error: string }

/** How a personal key is presented to auth-mcp: `stk_mcp_<client_id>.<secret>`. */
export const PERSONAL_KEY_PREFIX = 'stk_mcp_'

const NEGATIVE_TTL_MS = 5_000
const MAX_ENTRIES = 5_000
/** The invalidation channel's namespace for revoked keys (cache/runtime.ts). */
const REVOKED_NS = 'delegated.revoked'

export class DelegatedTokenService {
  private cache = new Map<string, { result: DelegatedResult; until: number }>()

  constructor() {
    // A key revoked on any replica: its cached answers go here too (no key: drop everything).
    onInvalidate(REVOKED_NS, (clientId) => (clientId ? this.dropClient(clientId) : this.cache.clear()))
  }

  /** The deployment's ceiling only; the administrator's switch (mcp/settings.ts) is asked in resolve(). */
  get enabled(): boolean {
    return env.DELEGATED_TOKENS_ENABLED
  }

  /**
   * Cheap, UNVERIFIED discriminator: a JWT has three dot-separated parts and is somebody else's
   * (ServiceAccount, OIDC). Hydra's opaque tokens are `ory_at_…` — anything else is still asked,
   * because the prefix is configurable, and introspection is what decides.
   */
  looksOpaque(token: string): boolean {
    // A personal key (`stk_mcp_<id>.<secret>`) is a secret, never a token: it is exchanged, not
    // introspected, and must not be sent to Hydra's introspection.
    return token.split('.').length !== 3 && !token.startsWith(PERSONAL_KEY_PREFIX)
  }

  async resolve(token: string, now: number = Date.now()): Promise<DelegatedResult> {
    if (!this.enabled) return { error: 'delegated_tokens_disabled' }
    if (!env.DELEGATED_TOKEN_AUDIENCE) return { error: 'delegated_audience_unset' }
    // The administrator's switch, asked on every call — before the cache, so turning MCP off refuses
    // tokens already cached, and turning it back on restores them.
    const gate = await mcpGate()
    if (!gate.on) return { error: gate.off === 'unavailable' ? 'mcp_settings_unavailable' : 'mcp_disabled' }

    const key = createHash('sha256').update(token).digest('hex')
    ensureBus()
    const hit = this.cache.get(key)
    // Served from memory only while revocations from other replicas are reaching this one.
    if (hit && now < hit.until && getStore().busHealthy()) return this.used(await this.current(hit.result, gate.settings), now)
    if (hit) this.cache.delete(key)

    const evaluated = await this.evaluate(token, now)
    const result = this.used(await this.current(evaluated, gate.settings), now)
    // What is cached is the token's own answer; the holder's groups and rights are re-read every call.
    const ttl = 'principal' in evaluated
      ? Math.min(env.DELEGATED_TOKEN_CACHE_MS, evaluated.principal.expiresAt - now)
      : NEGATIVE_TTL_MS
    if (ttl > 0) {
      if (this.cache.size >= MAX_ENTRIES) this.cache.clear()
      this.cache.set(key, { result: evaluated, until: now + ttl })
    }
    return result
  }

  /**
   * The cached answer made current: the holder's groups still allowed MCP, and a personal key's scopes
   * recomputed from what they hold now. "Could not tell" refuses (authz_unavailable), never guesses.
   */
  private async current(result: DelegatedResult, settings: McpSettings): Promise<DelegatedResult> {
    if (!('principal' in result)) return result
    const p = result.principal
    try {
      if (!groupAllowed(settings, (await rights(p.email)).groups)) return { error: 'mcp_group_not_allowed' }
      if (p.kind === 'oauth' && !settings.oauth.enabled) return { error: 'oauth_disabled' }
      const held = new Set(await platformScopes(p.email))
      const all = p.kind === 'personal' ? p.allPermissions : p.scopeMode === 'all'
      const scopes = all ? [...held] : p.scopes.filter((s) => held.has(s))
      const extra = p.tokenScope.split(' ').filter((s) => s && !isGrantableScope(s))
      const stepUpUntil = p.kind === 'oauth'
        ? oauthStepUpUntil(settings, { stepUpActions: p.stepUpActions === true, stepUpAt: p.stepUpAt, grantExpiresAt: p.grantExpiresAt })
        : null
      return {
        principal: {
          ...p, scopes: scopes.sort(), tokenScope: [...scopes.sort(), ...extra].join(' '),
          ...(p.kind === 'oauth' ? (stepUpUntil ? { stepUpUntil } : { stepUpUntil: undefined }) : {}),
        },
      }
    } catch (err) {
      log().warn({ reason: (err as Error).message }, 'could not read what the holder holds (deny)')
      return { error: 'authz_unavailable' }
    }
  }

  /** A token accepted: its key or sign-in was used (throttled, never awaited) — kuma's "last used". */
  private used(result: DelegatedResult, now: number): DelegatedResult {
    if ('principal' in result) touchApiKeyUse(result.principal.clientId, now)
    return result
  }

  clearCache(): void {
    this.cache.clear()
  }

  /**
   * A key was revoked: its cached tokens are asked again at once on every replica, not after the
   * window — and Hydra, the client deleted, answers them inactive or unknown.
   */
  forgetClient(clientId: string): void {
    broadcastInvalidation(REVOKED_NS, clientId)
  }

  private dropClient(clientId: string): void {
    for (const [key, { result }] of this.cache) {
      if ('principal' in result && result.principal.clientId === clientId) this.cache.delete(key)
    }
  }

  private async evaluate(token: string, now: number): Promise<DelegatedResult> {
    let intro: HydraIntrospection
    try {
      intro = await hydraService.introspect(token)
    } catch (err) {
      log().warn({ reason: (err as Error).message }, 'introspection failed (deny)')
      return { error: 'introspection_unavailable' }
    }
    if (!intro.active) return { error: 'token_inactive' }
    if (intro.token_use && intro.token_use !== 'access_token') return { error: 'not_an_access_token' }
    if (typeof intro.exp !== 'number' || intro.exp * 1000 <= now) return { error: 'token_expired' }
    if (!Array.isArray(intro.aud) || !intro.aud.includes(env.DELEGATED_TOKEN_AUDIENCE)) return { error: 'audience_mismatch' }
    if (!intro.client_id || !intro.sub) return { error: 'token_incomplete' }

    const bound = intro.sub === intro.client_id ? await this.personalKey(intro.client_id, now) : await this.oauth(intro, now)
    if ('error' in bound) return bound

    let email = ''
    let name = 'unknown'
    try {
      const identity = await kratosService.getIdentity(bound.subject)
      if (identity.state && identity.state !== 'active') return { error: 'subject_inactive' }
      const traits = (identity.traits ?? {}) as Record<string, unknown>
      email = typeof traits.email === 'string' ? traits.email : ''
      const n = traits.name
      name = typeof n === 'string' ? n : n && typeof n === 'object' ? Object.values(n).filter((v) => typeof v === 'string').join(' ') || 'unknown' : 'unknown'
    } catch (err) {
      log().warn({ reason: (err as Error).message }, 'subject lookup failed (deny)')
      return { error: 'subject_unknown' }
    }
    if (!email) return { error: 'subject_unknown' }

    return {
      principal: {
        subject: bound.subject,
        email,
        name,
        clientId: intro.client_id,
        scopes: [...new Set((intro.scope ?? '').split(' ').filter(isGrantableScope))].sort(),
        ...(bound.org ? { org: bound.org } : {}),
        kind: bound.kind,
        ...(bound.kind === 'personal' ? { allPermissions: bound.allPermissions } : {}),
        expiresAt: Math.min(intro.exp * 1000, bound.expiresAt ?? Infinity),
        tokenScope: intro.scope ?? '',
        aud: intro.aud,
        ...(bound.kind === 'personal' ? { keyExpiresAt: bound.expiresAt, keyStepUpAt: bound.keyStepUpAt, keyStepUpActions: bound.keyStepUpActions } : {}),
        ...(bound.kind === 'oauth' ? bound.oauth : {}),
      },
    }
  }

  private async oauth(intro: HydraIntrospection, now: number): Promise<Bound> {
    const subject = intro.sub as string
    const clientId = intro.client_id as string
    let client
    try {
      client = await hydraService.getClient(clientId)
    } catch {
      return { error: 'client_unknown' }
    }
    const meta = (client.metadata ?? {}) as Record<string, unknown>
    // Only a browser sign-in of an MCP registration acts as a person through auth-mcp.
    if (meta.kind !== 'mcp_oauth') return { error: 'not_an_mcp_client' }
    if (typeof meta.bound_subject === 'string' && meta.bound_subject && meta.bound_subject !== subject) return { error: 'client_bound_elsewhere' }
    const ext = intro.ext ?? {}
    const grantEnd = typeof ext.grant_expires_at === 'string' ? Date.parse(ext.grant_expires_at) : NaN
    // Mandatory absolute end, stamped at consent: a sign-in without one is refused, never eternal.
    if (!(grantEnd > now)) {
      this.expireGrant(subject, clientId, typeof client.client_name === 'string' ? client.client_name : null)
      return { error: 'grant_expired' }
    }
    const org = ext.org
    // The consent-time proof, or a later one the person gave through a step-up link (oauth/step-up-refresh.ts).
    const consented = typeof ext.second_factor_at === 'string' && ext.second_factor_at ? ext.second_factor_at : undefined
    const stepUpAt = laterProof(consented, ext.step_up_actions === true ? await refreshedOAuthProof(subject, clientId) : null)
    return {
      subject,
      kind: 'oauth',
      expiresAt: grantEnd,
      ...(typeof org === 'string' && org ? { org } : {}),
      oauth: {
        scopeMode: ext.scope_mode === 'chosen' ? 'chosen' : 'all',
        ...(stepUpAt ? { stepUpAt } : {}),
        stepUpActions: ext.step_up_actions === true,
        grantExpiresAt: grantEnd,
        clientName: client.client_name || 'MCP client',
      },
    }
  }

  private expired = new Set<string>()

  /** A sign-in past its absolute end: revoked at Hydra in the background, once per replica. */
  private expireGrant(subject: string, clientId: string, clientName: string | null): void {
    const key = `${subject}\0${clientId}`
    if (this.expired.has(key)) return
    if (this.expired.size >= MAX_ENTRIES) this.expired.clear()
    this.expired.add(key)
    void hydraFlows.revokeConsentSessions(subject, clientId).then(() => {
      oauthAudit('mcp.oauth.grant_expired', { actor: { id: subject, email: null, type: 'system' }, targetId: clientId, details: { client_name: clientName } })
    }).catch((err) => {
      this.expired.delete(key)
      log().warn({ reason: (err as Error).message }, 'could not revoke an expired sign-in')
    })
  }

  private async personalKey(clientId: string, now: number): Promise<Bound> {
    let meta: Record<string, unknown>
    try {
      meta = ((await hydraService.getClient(clientId)).metadata ?? {}) as Record<string, unknown>
    } catch {
      return { error: 'client_unknown' }
    }
    // An org machine key authenticates a machine, never a person.
    if (meta.kind !== 'personal') return { error: 'not_a_user_token' }
    const subject = meta.subject
    const expiresAt = typeof meta.expires_at === 'string' ? Date.parse(meta.expires_at) : NaN
    if (typeof subject !== 'string' || !subject) return { error: 'client_incomplete' }
    // Mandatory expiry: a personal key without one is refused, not treated as eternal.
    if (!(expiresAt > now)) return { error: 'key_expired' }
    const stepUpAt = typeof meta.step_up_at === 'string' ? meta.step_up_at : undefined
    return { subject, kind: 'personal', expiresAt, allPermissions: allPermissionsKey(meta), ...(stepUpAt ? { keyStepUpAt: stepUpAt } : {}), keyStepUpActions: meta.step_up_actions !== false }
  }
}

type OAuthFacts = Pick<DelegatedPrincipal, 'scopeMode' | 'stepUpAt' | 'stepUpActions' | 'grantExpiresAt' | 'clientName'>

type Bound =
  | { subject: string; kind: 'oauth' | 'personal'; org?: string; expiresAt?: number; allPermissions?: boolean; keyStepUpAt?: string; keyStepUpActions?: boolean; oauth?: OAuthFacts }
  | { error: string }

/** A personal key carrying all its holder's permissions (`scope_mode: all`) rather than a stored subset. */
export function allPermissionsKey(meta: Record<string, unknown> | undefined): boolean {
  return meta?.scope_mode === 'all'
}

export const delegatedTokenService = new DelegatedTokenService()
