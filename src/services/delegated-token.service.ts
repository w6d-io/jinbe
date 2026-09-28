import { createHash } from 'node:crypto'
import { env } from '../config/index.js'
import { hydraService, type HydraIntrospection } from './hydra.service.js'
import { kratosService } from './kratos.service.js'
import { getApiKeyPolicy } from './api-key-policy.js'
import { isGrantableScope } from './authorization-resolution.js'
import { componentLogger } from '../telemetry/logger.js'
import { touchApiKeyUse } from './api-key-last-used.js'
import { mcpGate, orgAllowed } from '../mcp/settings.js'

const log = () => componentLogger('delegated-token')

/**
 * A USER acting through a client, proven by an opaque Hydra access token (MCP prerequisite).
 *
 * Two ways in, one shape out:
 *   - an OAuth token (authorization code): `sub` is the user, `ext.org` the ONE organization the user
 *     picked at consent;
 *   - a personal key (client_credentials, `owner = user:<id>`): `sub` is the client, and the user and
 *     org are read from the client's own metadata, re-read on every introspection — so revoking the
 *     key, letting it expire, or the org forbidding personal keys stops it within the cache window.
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
  /** Grantable scopes only (resource:verb) — `mcp`, `offline_access` and wildcards are dropped. */
  scopes: string[]
  org: string
  kind: 'oauth' | 'personal'
  /** ms since epoch. */
  expiresAt: number
  /** The scope string as Hydra granted it (with `mcp`, `offline_access`) — for /api/mcp/token-info. */
  tokenScope: string
  /** The introspected audience. */
  aud: string[]
  /** Personal keys: the key's own expiry (ms since epoch). */
  keyExpiresAt?: number
}

export type DelegatedResult = { principal: DelegatedPrincipal } | { error: string }

/** How a personal key is presented to auth-mcp: `stk_mcp_<client_id>.<secret>`. */
export const PERSONAL_KEY_PREFIX = 'stk_mcp_'

const NEGATIVE_TTL_MS = 5_000
const MAX_ENTRIES = 5_000

export class DelegatedTokenService {
  private cache = new Map<string, { result: DelegatedResult; until: number }>()

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
    // The administrator's switch and org scope, asked on every call — before the cache, so turning MCP
    // off (or an org out of scope) refuses tokens already cached, and turning it back on restores them.
    const gate = await mcpGate()
    if (!gate.on) return { error: gate.off === 'unavailable' ? 'mcp_settings_unavailable' : 'mcp_disabled' }

    const key = createHash('sha256').update(token).digest('hex')
    const hit = this.cache.get(key)
    if (hit && now < hit.until) return this.used(this.inScope(hit.result, gate.settings), now)
    if (hit) this.cache.delete(key)

    const evaluated = await this.evaluate(token, now)
    const result = this.used(this.inScope(evaluated, gate.settings), now)
    // What is cached is the token's own answer; the org scope is re-applied on every hit.
    const ttl = 'principal' in evaluated
      ? Math.min(env.DELEGATED_TOKEN_CACHE_MS, evaluated.principal.expiresAt - now)
      : NEGATIVE_TTL_MS
    if (ttl > 0) {
      if (this.cache.size >= MAX_ENTRIES) this.cache.clear()
      this.cache.set(key, { result: evaluated, until: now + ttl })
    }
    return result
  }

  private inScope(result: DelegatedResult, settings: Parameters<typeof orgAllowed>[0]): DelegatedResult {
    if ('principal' in result && !orgAllowed(settings, result.principal.org)) return { error: 'mcp_org_not_allowed' }
    return result
  }

  /** A personal key's token accepted: the key was used (throttled, never awaited). */
  private used(result: DelegatedResult, now: number): DelegatedResult {
    if ('principal' in result && result.principal.kind === 'personal') touchApiKeyUse(result.principal.clientId, now)
    return result
  }

  clearCache(): void {
    this.cache.clear()
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

    const bound = intro.sub === intro.client_id ? await this.personalKey(intro.client_id, now) : this.oauth(intro)
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
        org: bound.org,
        kind: bound.kind,
        expiresAt: Math.min(intro.exp * 1000, bound.expiresAt ?? Infinity),
        tokenScope: intro.scope ?? '',
        aud: intro.aud,
        ...(bound.kind === 'personal' ? { keyExpiresAt: bound.expiresAt } : {}),
      },
    }
  }

  private oauth(intro: HydraIntrospection): { subject: string; org: string; kind: 'oauth'; expiresAt?: number } | { error: string } {
    const org = intro.ext?.org
    if (typeof org !== 'string' || org === '') return { error: 'token_not_org_bound' }
    return { subject: intro.sub as string, org, kind: 'oauth' }
  }

  private async personalKey(clientId: string, now: number): Promise<{ subject: string; org: string; kind: 'personal'; expiresAt: number } | { error: string }> {
    let meta: Record<string, unknown>
    try {
      meta = ((await hydraService.getClient(clientId)).metadata ?? {}) as Record<string, unknown>
    } catch {
      return { error: 'client_unknown' }
    }
    // An org machine key authenticates a machine, never a person.
    if (meta.kind !== 'personal') return { error: 'not_a_user_token' }
    const subject = meta.subject
    const org = meta.organization_id
    const expiresAt = typeof meta.expires_at === 'string' ? Date.parse(meta.expires_at) : NaN
    if (typeof subject !== 'string' || !subject || typeof org !== 'string' || !org) return { error: 'client_incomplete' }
    // Mandatory expiry: a personal key without one is refused, not treated as eternal.
    if (!(expiresAt > now)) return { error: 'key_expired' }
    try {
      if ((await getApiKeyPolicy(org)).personal_keys !== 'allowed') return { error: 'personal_keys_forbidden' }
    } catch {
      return { error: 'policy_unavailable' }
    }
    return { subject, org, kind: 'personal', expiresAt }
  }
}

export const delegatedTokenService = new DelegatedTokenService()
