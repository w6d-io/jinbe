import { rights } from '../authz/opa.js'
import { SwrCache } from '../cache/swr.js'
import { getRedisClient } from '../services/redis-client.service.js'
import { KratosApiError, kratosService } from '../services/kratos.service.js'
import { KratosSessionService, kratosSessionService, type KratosAuthenticationMethod } from '../services/kratos-session.service.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'
import { IMPERSONATE, impersonationAudit, impersonationEnabled, impersonationToken, publicIdentity, targetProblem, type TargetProblem } from './service.js'
import { impersonationStore, type ImpersonationGrant } from './store.js'

/**
 * The gateway's question, on every request that carries the impersonation cookie: "who is this?".
 *
 * 200 — with a body shaped like a Kratos session whose identity is the impersonated user — only when
 * ALL of this holds; anything else is a refusal, which the gateway turns into its 401 (it never falls
 * back to the administrator's own session):
 *
 *   1. impersonation is on;
 *   2. the cookie maps to a live grant;
 *   3. the request also carries the administrator's Kratos session cookie, and that session is
 *      valid, belongs to the grant's administrator, IS the session that started the grant, and is at
 *      aal2 — the impersonation cookie alone, copied out of a browser, opens nothing;
 *   4. the method is GET, HEAD or OPTIONS (the gateway forwards the original method);
 *   5. the administrator still holds users:impersonate, and the user is still somebody who may be
 *      impersonated (active, not a super admin). A grant that fails this is ended, not just refused.
 *
 * Asked on every request of a browsing session, so everything but the grant lookup is answered from
 * a few seconds of memory: the session validation (the session cache, reads only), the
 * administrator's rights (the policy answers cache) and the user (TARGET_TTL_MS here).
 */

const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const TARGET_TTL_MS = 5_000
/** One `used` event per grant and host per this long; one `write_refused` per minute. */
const USE_TRACE_S = 600
const WRITE_TRACE_S = 60

export type CheckRefusal =
  | 'impersonation_disabled'
  | 'impersonation_cookie_missing'
  | 'impersonation_grant_invalid'
  | 'impersonation_admin_session_missing'
  | 'impersonation_admin_session_invalid'
  | 'impersonation_admin_session_mismatch'
  | 'impersonation_admin_aal'
  | 'impersonation_read_only'
  | 'impersonation_permission_revoked'
  | 'impersonation_unverifiable'
  | TargetProblem

/** What the gateway reads as the session (`subject_from: identity.id`, `extra_from: @this`). */
export interface ImpersonatedSession {
  id: string
  active: true
  expires_at: string
  authenticated_at: string
  /** The ADMINISTRATOR's: the level and the factors actually proven by the person at the keyboard. */
  authenticator_assurance_level: string
  authentication_methods: KratosAuthenticationMethod[]
  /** The impersonated user, as their own session would show them. */
  identity: ReturnType<typeof publicIdentity>
  impersonator: { id: string; email: string; session_id: string }
}

export type CheckResult =
  | { ok: true; session: ImpersonatedSession; grant: ImpersonationGrant }
  | { ok: false; reason: CheckRefusal; grant?: ImpersonationGrant }

export interface CheckInput {
  method: string
  cookieHeader: string | undefined
  /** The site being browsed (X-Forwarded-Host), for the trail only. */
  host: string | null
}

type Target = { identity: KratosIdentity | null; problem: TargetProblem | null }

const targets = new SwrCache<Target>({ namespace: 'impersonation.target', freshMs: TARGET_TTL_MS, staleMs: TARGET_TTL_MS, local: true, l1Max: 1_000 })

/** The user and whether they may still be impersonated. Throws when Kratos or the policy cannot say. */
function target(id: string): Promise<Target> {
  return targets.get(id, async () => {
    let identity: KratosIdentity | null
    try {
      identity = await kratosService.getIdentity(id)
    } catch (err) {
      if (!(err instanceof KratosApiError && err.statusCode === 404)) throw err
      identity = null
    }
    return { identity, problem: await targetProblem(identity) }
  })
}

// ── the trail: sampled, never one event per request ────────────────────────────

const traced = new Map<string, number>()

/** True the first time a key is seen in its window, on this replica and (Redis) on all of them. */
async function firstInWindow(key: string, seconds: number, now: number): Promise<boolean> {
  if ((traced.get(key) ?? 0) > now) return false
  if (traced.size >= 5_000) traced.clear()
  traced.set(key, now + seconds * 1000)
  try {
    return (await getRedisClient().set(`jinbe:impersonation:seen:${key}`, '1', 'EX', seconds, 'NX')) === 'OK'
  } catch {
    // Redis down: record it rather than lose it — a duplicate is cheaper than a gap.
    return true
  }
}

async function trace(event: 'impersonation.used' | 'impersonation.write_refused', grant: ImpersonationGrant, input: CheckInput, now: number): Promise<void> {
  const host = input.host ?? 'unknown'
  const refused = event === 'impersonation.write_refused'
  if (!(await firstInWindow(`${refused ? 'w' : 'u'}:${grant.id}:${host}`, refused ? WRITE_TRACE_S : USE_TRACE_S, now))) return
  impersonationAudit(event, grant, { details: { host, ...(refused ? { method: input.method } : {}) } })
}

/** A grant that can no longer stand (rights withdrawn, the user promoted or gone): ended and said so. */
async function end(grant: ImpersonationGrant, reason: CheckRefusal): Promise<void> {
  const live = await impersonationStore.endForSession(grant.adminSessionId).catch(() => null)
  if (live?.id === grant.id) impersonationAudit('impersonation.stopped', grant, { details: { ended: reason } })
}

export async function checkImpersonation(input: CheckInput, now: number = Date.now()): Promise<CheckResult> {
  if (!impersonationEnabled()) return { ok: false, reason: 'impersonation_disabled' }
  const token = impersonationToken(input.cookieHeader)
  if (!token) return { ok: false, reason: 'impersonation_cookie_missing' }
  const grant = await impersonationStore.byToken(token, now)
  if (!grant) return { ok: false, reason: 'impersonation_grant_invalid' }
  const refuse = (reason: CheckRefusal): CheckResult => ({ ok: false, reason, grant })

  // The administrator's own session, validated here from the cookie and nothing else: a bearer
  // token or a ServiceAccount beside the cookie proves nothing about who is browsing.
  const sessionCookie = KratosSessionService.extractSessionCookie(input.cookieHeader)
  if (!sessionCookie) return refuse('impersonation_admin_session_missing')
  const { session } = await kratosSessionService.validateSession(sessionCookie, { allowCached: true })
  if (!session) return refuse('impersonation_admin_session_invalid')
  if (session.identityId !== grant.adminId || session.sessionId !== grant.adminSessionId) return refuse('impersonation_admin_session_mismatch')
  if (session.aal !== 'aal2') return refuse('impersonation_admin_aal')

  if (!READ_METHODS.has(input.method.toUpperCase())) {
    await trace('impersonation.write_refused', grant, input, now)
    return refuse('impersonation_read_only')
  }

  let held: string[]
  let user: Target
  try {
    held = (await rights(session.email)).permissions
    user = await target(grant.targetId)
  } catch {
    // Kratos or the policy could not be asked: refused for now, the grant stays.
    return refuse('impersonation_unverifiable')
  }
  if (!held.includes(IMPERSONATE)) {
    await end(grant, 'impersonation_permission_revoked')
    return refuse('impersonation_permission_revoked')
  }
  if (user.problem || !user.identity) {
    const reason = user.problem ?? 'impersonation_target_unavailable'
    await end(grant, reason)
    return refuse(reason)
  }

  await trace('impersonation.used', grant, input, now)
  return {
    ok: true,
    grant,
    session: {
      id: `impersonation:${grant.id}`,
      active: true,
      expires_at: grant.expiresAt,
      authenticated_at: grant.startedAt,
      authenticator_assurance_level: session.aal,
      authentication_methods: session.authenticationMethods ?? [],
      identity: publicIdentity(user.identity),
      impersonator: { id: grant.adminId, email: session.email, session_id: grant.adminSessionId },
    },
  }
}

/** Test seam. */
export function resetImpersonationCheck(): void {
  traced.clear()
  targets.resetLocal()
}
