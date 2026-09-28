import { createHmac, randomBytes } from 'node:crypto'
import { env } from '../config/index.js'
import { broadcastInvalidation, cacheEnabled, ensureBus, onInvalidate } from '../cache/swr.js'
import { cacheRequests } from '../telemetry/metrics.js'

/**
 * Kratos Session Identity (from toSession response)
 */
export interface KratosSessionIdentity {
  id: string
  schema_id: string
  traits: {
    email: string
    name?: string
    picture?: string
    providers?: Array<{
      name: string
      issuer_url: string
      provider_type: string
    }>
  }
  state: string
  created_at: string
  updated_at: string
}

/**
 * Kratos Session response from /sessions/whoami
 */
export interface KratosAuthenticationMethod {
  method?: string
  aal?: string
  completed_at?: string
}

export interface KratosSession {
  id: string
  active: boolean
  expires_at: string
  authenticated_at: string
  authenticator_assurance_level: string
  authentication_methods?: KratosAuthenticationMethod[]
  identity: KratosSessionIdentity
}

/**
 * When the SECOND factor was last proven, which is a different clock from the session's
 * `authenticated_at`.
 *
 * `authenticated_at` is stamped by the FIRST factor and a plain aal2 step-up does not move it —
 * measured on a live session: password at 08:17:06, TOTP at 08:17:45, `authenticated_at` still
 * 08:17:06. A step-up gate reading it therefore keeps refusing a factor that was just proven.
 *
 * Returns null when no aal2 method carries a timestamp, so the gate fails closed rather than
 * treating an unknown age as fresh.
 */
export function secondFactorProvenAt(session: KratosSession): Date | null {
  const proofs = (session.authentication_methods ?? [])
    .filter((m) => m.aal === 'aal2' && !!m.completed_at)
    .map((m) => new Date(m.completed_at as string).getTime())
    .filter((t) => Number.isFinite(t))
  return proofs.length > 0 ? new Date(Math.max(...proofs)) : null
}

/**
 * Validated session result
 */
export interface ValidatedSession {
  sessionId: string
  email: string
  identityId: string
  name?: string
  picture?: string
  expiresAt: Date
  active: boolean
  // Second-factor state, used by the privileged-action step-up gate (R2).
  aal: string // authenticator_assurance_level: "aal1" | "aal2"
  authenticatedAt: Date // FIRST-factor time; not moved by an aal2 step-up
  secondFactorAt: Date | null // when aal2 was last proven; null when never
}

/**
 * Session validation result with error info
 */
export interface SessionValidationResult {
  session: ValidatedSession | null
  error?: string
  /** Answered from the short validation cache, not by Kratos just now. */
  cached?: boolean
}

/**
 * A very short, per-replica cache of SUCCESSFUL session validations, for reads only.
 *
 * Every request used to ask Kratos /sessions/whoami (sandbox: p50 2.8ms, p95 85ms at Kratos alone).
 * A console opening fires dozens of reads with the same cookie within a second.
 *
 *   - Keyed by an HMAC of the cookie under a per-process random key: the raw cookie is never stored,
 *     and the key is useless outside this process. Process memory only — never Redis.
 *   - Reads only: the caller opts in (`allowCached`), and the identity extractor does so for
 *     GET/HEAD/OPTIONS. A write — every step-up gate, every mutation — always asks Kratos, so a revoked
 *     session can never change anything, and a second factor just proven is always seen.
 *   - Lives SESSION_CACHE_TTL_MS (default 5s, max 10s), never past the session's own expiry. Failures
 *     are not cached (a fresh login works at once).
 *   - Dropped on every replica, via the cache invalidation channel, when jinbe revokes a session, all
 *     of an identity's sessions, deletes or changes the identity or its second factors, and when the
 *     Kratos webhook reports a login or settings change for the identity.
 *
 * The trade-off, stated: a session revoked OUTSIDE jinbe — Kratos logout, "revoke other sessions" in
 * the account settings, an admin call made directly to Kratos — can still make READS to jinbe for up
 * to the TTL on the replicas that had cached it. It can never write. Kill switch: SESSION_CACHE_TTL_MS=0,
 * CACHE_ENABLED=false, or `kratos.session` in CACHE_DISABLED_NAMESPACES.
 */
const SESSION_NS = 'kratos.session'
const MAX_ENTRIES = 10_000
const hmacKey = randomBytes(32)
const sessionCache = new Map<string, { session: ValidatedSession; until: number }>()
/** Reads of one cookie arriving together (a console opening) share ONE validation. */
const inflight = new Map<string, Promise<SessionValidationResult>>()
/** Bumped by every revocation: a validation that started before one is answered but never kept. */
let generation = 0

const cacheKeyOf = (cookie: string) => createHmac('sha256', hmacKey).update(cookie).digest('base64url')
const sessionTtlMs = () => (cacheEnabled(SESSION_NS) ? Math.min(Math.max(env.SESSION_CACHE_TTL_MS ?? 5_000, 0), 10_000) : 0)

function dropLocal(key?: string): void {
  // A validation in flight may predate the revocation: later reads must not join it, and it must
  // not store what it gets.
  generation++
  inflight.clear()
  if (!key) return sessionCache.clear()
  const [kind, id] = [key.slice(0, 4), key.slice(4)]
  for (const [k, e] of sessionCache) {
    if ((kind === 'sid:' && e.session.sessionId === id) || (kind === 'iid:' && e.session.identityId === id)) sessionCache.delete(k)
  }
}
onInvalidate(SESSION_NS, dropLocal)

/** jinbe revoked this session (or learned it ended): no replica may keep serving it from cache. */
export function forgetSession(sessionId: string): void {
  broadcastInvalidation(SESSION_NS, `sid:${sessionId}`)
}

/** Every session of this identity (revoked, deleted, deactivated, second factors changed, re-authenticated). */
export function forgetSessionsOf(identityId: string): void {
  broadcastInvalidation(SESSION_NS, `iid:${identityId}`)
}

/** Test seam. */
export function clearSessionCache(): void {
  sessionCache.clear()
  inflight.clear()
}

/**
 * Kratos Public API Service
 * Handles session validation via Ory Kratos Public API
 */
export class KratosSessionService {
  private publicUrl: string

  constructor() {
    this.publicUrl = env.KRATOS_PUBLIC_URL
  }

  /**
   * Validate session by calling Kratos /sessions/whoami
   * This endpoint validates the ory_kratos_session cookie
   *
   * @param sessionCookie - The ory_kratos_session cookie value
   * @returns SessionValidationResult with session if valid, or error message if invalid
   */
  async validateSession(sessionCookie: string, opts: { allowCached?: boolean } = {}): Promise<SessionValidationResult> {
    const ttl = sessionTtlMs()
    const key = ttl > 0 ? cacheKeyOf(sessionCookie) : null
    if (key && opts.allowCached) {
      const hit = sessionCache.get(key)
      if (hit && Date.now() < hit.until) {
        cacheRequests.inc({ namespace: SESSION_NS, result: 'hit' })
        return { session: hit.session, cached: true }
      }
      cacheRequests.inc({ namespace: SESSION_NS, result: 'miss' })
      const running = inflight.get(key)
      if (running) return running
      const p = this.validateAndRemember(sessionCookie, key, ttl)
      inflight.set(key, p)
      void p.finally(() => { if (inflight.get(key) === p) inflight.delete(key) })
      return p
    }
    return this.validateAndRemember(sessionCookie, key, ttl)
  }

  private async validateAndRemember(sessionCookie: string, key: string | null, ttl: number): Promise<SessionValidationResult> {
    const startedAt = generation
    const result = await this.askKratos(sessionCookie)
    // Remembered after ANY successful validation, so a write's fresh answer also refreshes the reads.
    if (key && result.session && startedAt === generation) {
      // Listening for other replicas' revocations before holding anything they could revoke.
      ensureBus()
      if (sessionCache.size >= MAX_ENTRIES) sessionCache.delete(sessionCache.keys().next().value as string)
      sessionCache.set(key, { session: result.session, until: Math.min(Date.now() + ttl, result.session.expiresAt.getTime()) })
    } else if (key) {
      sessionCache.delete(key)
    }
    return result
  }

  private async askKratos(sessionCookie: string): Promise<SessionValidationResult> {
    try {
      const url = `${this.publicUrl}/sessions/whoami`

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          // Either the cookies as extracted (`name=value; …`) or a bare value under the default name.
          Cookie: sessionCookie.includes('=') ? sessionCookie : `ory_kratos_session=${sessionCookie}`,
        },
      })

      if (!response.ok) {
        // 401 = session invalid/expired, 403 = no session
        if (response.status === 401) {
          return { session: null, error: 'Session expired or invalid' }
        }
        if (response.status === 403) {
          return { session: null, error: 'No active session' }
        }
        return { session: null, error: `Kratos error: ${response.status} ${response.statusText}` }
      }

      const session = (await response.json()) as KratosSession

      // Check if session is active
      if (!session.active) {
        return { session: null, error: 'Session is not active' }
      }

      // Check if session is expired
      const expiresAt = new Date(session.expires_at)
      if (expiresAt < new Date()) {
        return { session: null, error: 'Session has expired' }
      }

      return {
        session: {
          sessionId: session.id,
          email: session.identity.traits.email,
          identityId: session.identity.id,
          name: session.identity.traits.name || undefined,
          picture: session.identity.traits.picture || undefined,
          expiresAt,
          active: session.active,
          aal: session.authenticator_assurance_level,
          authenticatedAt: new Date(session.authenticated_at),
          secondFactorAt: secondFactorProvenAt(session),
        },
      }
    } catch (error) {
      console.error('Kratos session validation error:', error)
      return { session: null, error: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}` }
    }
  }

  /**
   * The session cookies to hand to Kratos, as `name=value[; name=value]`. The cookie's name is
   * Kratos' own setting (session.cookie.name — e.g. ory_kratos_session_sandbox), so every
   * `ory_kratos_session*` cookie is forwarded and Kratos picks the one it issued. Other cookies
   * (analytics, CSRF) never leave this process.
   */
  static extractSessionCookie(cookieHeader: string | undefined): string | null {
    if (!cookieHeader) return null
    const session = cookieHeader
      .split(';')
      .map((c) => c.trim())
      .filter((c) => /^ory_kratos_session[A-Za-z0-9_-]*=/.test(c))
    return session.length > 0 ? session.join('; ') : null
  }
}

export const kratosSessionService = new KratosSessionService()
