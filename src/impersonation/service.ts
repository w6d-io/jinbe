import { env } from '../config/env.js'
import { rights } from '../authz/opa.js'
import { ROLES } from '../policy/roles.js'
import { sitesConfig } from '../sites/config.js'
import { auditEventService, type AuditActor } from '../services/audit-event.service.js'
import { catalogEntry, type AuditEventType } from '../audit/v1/catalog.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'
import type { ImpersonationGrant } from './store.js'

/**
 * Impersonation: an administrator holding `users:impersonate` browses the sites behind the gateway as
 * one user, READ-ONLY, for a bounded time. Off unless IMPERSONATION_ENABLED.
 *
 *   console (kuma → jinbe, the administrator's session)
 *     POST   /api/admin/users/:id/impersonate   start: a grant in Redis, the impersonation cookie set
 *     GET    /api/admin/impersonation           is it on, may I, what is running on this session
 *     DELETE /api/admin/impersonation           stop: grant deleted, cookie cleared
 *   gateway (Oathkeeper → jinbe, per request carrying the cookie)
 *     ANY    /api/oathkeeper/impersonation/session   200 with a session-shaped body for the user, or 401
 *
 * No Kratos session exists for the user, and nothing is sent to them. jinbe and the console never
 * read the cookie: there the administrator is themselves (the identity extractor takes only
 * `ory_kratos_session*`, and the cookie may not be named like one). At the gateway the cookie alone
 * opens nothing: every request must also carry the administrator's own session cookie, still valid,
 * the same session that started the grant, at aal2 (check.ts).
 *
 * Who can never be impersonated: oneself, a member of super_admins (or a holder of the super_admin
 * role by any other way), a machine identity, an inactive or unknown one.
 */

export const IMPERSONATE = 'users:impersonate'

/** The shortest grant; the longest is IMPERSONATION_MAX_MINUTES, which a request that names none gets. */
export const MIN_MINUTES = 5

export const impersonationEnabled = (): boolean => env.IMPERSONATION_ENABLED === true

export type TargetProblem = 'impersonation_target_admin' | 'impersonation_target_unavailable'

const groupsOf = (identity: KratosIdentity): string[] => {
  const groups = (identity.metadata_admin as { groups?: unknown } | null | undefined)?.groups
  return Array.isArray(groups) ? groups.filter((g): g is string => typeof g === 'string') : []
}

export const emailOf = (identity: KratosIdentity): string | null => {
  const email = (identity.traits as { email?: unknown } | undefined)?.email
  return typeof email === 'string' && email ? email : null
}

export const nameOf = (identity: KratosIdentity): string => {
  const name = (identity.traits as { name?: unknown } | undefined)?.name
  return typeof name === 'string' ? name : ''
}

/**
 * Why this identity may not be impersonated, or null. Asked when a grant starts and again while it
 * runs (a user promoted, deactivated or deleted meanwhile ends it).
 *
 * super_admins is read from the identity AND asked of the policy: the group as Kratos holds it, and
 * the role however it is held (a direct grant binds no group). Throws AuthzUnavailableError when the
 * policy cannot say — the caller refuses, never guesses.
 */
export async function targetProblem(identity: KratosIdentity | null): Promise<TargetProblem | null> {
  if (!identity) return 'impersonation_target_unavailable'
  if (identity.state !== 'active') return 'impersonation_target_unavailable'
  const email = emailOf(identity)
  // No address: nothing the policy could decide on. A ServiceAccount's synthetic subject: a machine.
  if (!email || email.toLowerCase().endsWith(`@${env.K8S_SA_EMAIL_DOMAIN.toLowerCase()}`)) return 'impersonation_target_unavailable'
  const superGroup = ROLES.super_admin.group
  if (groupsOf(identity).includes(superGroup)) return 'impersonation_target_admin'
  const held = await rights(email)
  if (held.groups.includes(superGroup) || held.roles.includes('super_admin')) return 'impersonation_target_admin'
  return null
}

/** The identity as a session shows it: never the admin metadata, never credentials. */
export function publicIdentity(identity: KratosIdentity): Omit<KratosIdentity, 'metadata_admin' | 'credentials'> {
  const shown: Partial<KratosIdentity> = { ...identity }
  delete shown.metadata_admin
  delete shown.credentials
  return shown as Omit<KratosIdentity, 'metadata_admin' | 'credentials'>
}

export interface ActiveView {
  target: { id: string; email: string; name: string }
  reason: string
  startedAt: string
  expiresAt: string
  mode: 'read'
}

export function activeView(grant: ImpersonationGrant): ActiveView {
  return {
    target: { id: grant.targetId, email: grant.targetEmail, name: grant.targetName },
    reason: grant.reason,
    startedAt: grant.startedAt,
    expiresAt: grant.expiresAt,
    mode: 'read',
  }
}

// ── the cookie ─────────────────────────────────────────────────────────────────

/**
 * Scoped like the platform session cookie (SITES_COOKIE_DOMAIN), so it reaches every site host that
 * the session reaches: a host the session cookie does not reach could not be browsed anyway, since
 * the gateway check needs both. Without a cookie domain it is host-only (the API host): local
 * development, where one host serves everything.
 */
function cookie(value: string, maxAgeSeconds: number): string {
  const domain = sitesConfig().SITES_COOKIE_DOMAIN
  return [
    `${env.IMPERSONATION_COOKIE_NAME}=${value}`,
    ...(domain ? [`Domain=${domain}`] : []),
    'Path=/',
    `Max-Age=${maxAgeSeconds}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
  ].join('; ')
}

export const impersonationCookie = (token: string, maxAgeSeconds: number): string => cookie(token, maxAgeSeconds)
export const clearedImpersonationCookie = (): string => cookie('', 0)

/** The impersonation cookie's value in a Cookie header, by its exact name; null when absent or empty. */
export function impersonationToken(cookieHeader: string | undefined): string | null {
  if (!cookieHeader) return null
  const prefix = `${env.IMPERSONATION_COOKIE_NAME}=`
  const found = cookieHeader.split(';').map((c) => c.trim()).find((c) => c.startsWith(prefix))
  return found && found.length > prefix.length ? found.slice(prefix.length) : null
}

// ── audit ──────────────────────────────────────────────────────────────────────

/**
 * One audit/v1 event of impersonation (catalog `impersonation.*`): the administrator is the actor,
 * the user the target, the stated reason on every event. Fire-and-forget, like every emit.
 */
export function impersonationAudit(
  event: Extract<AuditEventType, `impersonation.${string}`>,
  grant: ImpersonationGrant,
  e: { actor?: Pick<AuditActor, 'ip' | 'ua'> & { requestId?: string | null }; details?: Record<string, unknown> } = {},
): void {
  const { severity } = catalogEntry(event)
  const refused = event === 'impersonation.write_refused'
  try {
    auditEventService.emit({
      category: event === 'impersonation.used' || refused ? 'access' : 'auth',
      kind: 'security',
      verb: event.split('.').at(-1) as string,
      target: `user:${grant.targetId}`,
      targetType: 'user',
      targetId: grant.targetId,
      result: refused ? 'denied' : 'applied',
      severity,
      reason: grant.reason,
      actor: { id: grant.adminId, email: grant.adminEmail, sessionId: grant.adminSessionId, ip: e.actor?.ip ?? null, ua: e.actor?.ua ?? null },
      requestId: e.actor?.requestId ?? null,
      details: { grantId: grant.id, reason: grant.reason, mode: 'read', startedAt: grant.startedAt, expiresAt: grant.expiresAt, ...(e.details ?? {}) },
      source: 'jinbe-api',
      v1Event: event,
    }).catch(() => {})
  } catch {
    // The emitter never throws; a mocked or half-initialised one must not fail the request.
  }
}
