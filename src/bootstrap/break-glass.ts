import { createHash, timingSafeEqual } from 'crypto'
import { getRedisClient } from '../services/redis-client.service.js'
import { kratosService } from '../services/kratos.service.js'
import { addToGroup, removeFromGroup } from '../services/organisation-store.js'
import { auditEventService } from '../services/audit-event.service.js'
import { opalPublisher } from '../services/opal-publisher.js'
import { invalidateAuthz } from '../authz/opa.js'
import { breakGlassUses } from '../telemetry/metrics.js'
import { ROLES } from '../policy/roles.js'
import { convergeJinbe } from './converge.js'

/**
 * BREAK-GLASS — the one emergency path (authz-v2-design §7). With no wildcard and no bypass, a broken
 * group or role definition could lock every administrator out. This restores DATA, it skips no check:
 *
 *   1. converges what jinbe owns (super_admin generated from the catalogue, the staff groups bound as
 *      code says) — repairing a definition somebody broke;
 *   2. puts ONE named identity in super_admins until a deadline (default 60 min, at most 240);
 *   3. records it (rbac:break_glass), audits it (`rbac.break_glass_used`, high — the alert), counts it
 *      (jinbe_break_glass_total), pushes it to OPA. Every guard then decides as usual: that person
 *      passes because they now hold everything, and still needs their second factor where a route
 *      asks for one.
 *   4. on the deadline the membership it added is taken away again (sweepBreakGlass, every minute in
 *      the server and on every bootstrap run) and audited (`rbac.break_glass_expired`). A person who
 *      was already a super admin keeps it.
 *
 * Who can trigger it: someone who can run a command in the jinbe pod (cluster access) AND holds the
 * offline code whose sha256 is JINBE_BREAK_GLASS_CODE_SHA256 (Vault). Without that variable the path
 * does not exist. `--dry-run` proves the code, the identity and the store without changing anything,
 * and is audited too (`rbac.break_glass_tested`): run it per environment after every rotation.
 */

export const BREAK_GLASS_KEY = 'rbac:break_glass'
export const BREAK_GLASS_MAX_MINUTES = 240

export interface BreakGlassGrant {
  email: string
  id: string
  reason: string
  at: string
  until: string
  /** Whether this grant added the membership (and so must take it away again). */
  added: boolean
}

export class BreakGlassError extends Error {}

function codeMatches(code: string, expectedSha256: string): boolean {
  const got = createHash('sha256').update(code, 'utf8').digest()
  const want = Buffer.from(expectedSha256.trim().toLowerCase(), 'hex')
  return want.length === got.length && timingSafeEqual(got, want)
}

interface Logger { info(obj: object, msg?: string): void; warn(obj: object, msg?: string): void; error(obj: object, msg?: string): void }

export async function breakGlass(opts: {
  email: string
  reason: string
  code: string
  expectedSha256: string | undefined
  minutes: number
  dryRun: boolean
  logger: Logger
}): Promise<BreakGlassGrant | { dryRun: true; email: string; id: string; alreadyMember: boolean }> {
  if (!opts.expectedSha256) throw new BreakGlassError('Break-glass is not configured here (JINBE_BREAK_GLASS_CODE_SHA256 is unset)')
  if (!codeMatches(opts.code, opts.expectedSha256)) {
    auditEventService.emit({ type: 'rbac.break_glass_refused', target: { type: 'user', id: opts.email }, result: 'denied', reason: 'wrong code', severity: 'high', actor: { email: 'break-glass', type: 'system' }, source: 'bootstrap' }).catch(() => {})
    throw new BreakGlassError('The break-glass code does not match')
  }
  if (!opts.reason.trim()) throw new BreakGlassError('A reason is required')
  const minutes = Math.min(Math.max(1, Math.round(opts.minutes)), BREAK_GLASS_MAX_MINUTES)
  const identity = await kratosService.findByEmail(opts.email)
  if (!identity) throw new BreakGlassError(`No identity with the address ${opts.email}`)
  const group = ROLES.super_admin.group
  const groups = (identity.metadata_admin as { groups?: unknown } | null)?.groups
  const alreadyMember = Array.isArray(groups) && groups.includes(group)

  if (opts.dryRun) {
    await getRedisClient().ping()
    auditEventService.emit({ type: 'rbac.break_glass_tested', target: { type: 'user', id: identity.id }, result: 'ok', reason: opts.reason, severity: 'info', actor: { email: 'break-glass', type: 'system' }, source: 'bootstrap' }).catch(() => {})
    return { dryRun: true, email: opts.email, id: identity.id, alreadyMember }
  }

  await convergeJinbe(opts.logger)
  if (!alreadyMember) {
    await kratosService.updateAdminState(identity.id, (s) => {
      const current = Array.isArray(s.metadataAdmin.groups) ? (s.metadataAdmin.groups as string[]) : []
      return { ...s, metadataAdmin: { ...s.metadataAdmin, groups: [...new Set([...current, group])] } }
    })
    await addToGroup(identity.id, group, 'break-glass')
  }
  const now = Date.now()
  const grant: BreakGlassGrant = {
    email: opts.email, id: identity.id, reason: opts.reason,
    at: new Date(now).toISOString(), until: new Date(now + minutes * 60_000).toISOString(), added: !alreadyMember,
  }
  await getRedisClient().set(BREAK_GLASS_KEY, JSON.stringify(grant))
  breakGlassUses.labels('used').inc()
  opts.logger.error({ grant }, 'BREAK-GLASS used: a super_admin membership was restored')
  auditEventService.emit({
    type: 'rbac.break_glass_used', target: { type: 'user', id: identity.id }, result: 'applied',
    reason: opts.reason, severity: 'high', actor: { email: 'break-glass', type: 'system' }, source: 'bootstrap',
    details: { until: grant.until, added: grant.added },
  }).catch(() => {})
  invalidateAuthz()
  await opalPublisher.refreshAll('break-glass')
  return grant
}

/** Takes an expired break-glass grant away again. Safe to call often; does nothing before the deadline. */
export async function sweepBreakGlass(logger: Pick<Logger, 'warn'>, now = Date.now()): Promise<BreakGlassGrant | null> {
  const redis = getRedisClient()
  const raw = await redis.get(BREAK_GLASS_KEY)
  if (!raw) return null
  let grant: BreakGlassGrant
  try {
    grant = JSON.parse(raw) as BreakGlassGrant
  } catch {
    await redis.del(BREAK_GLASS_KEY)
    return null
  }
  if (Date.parse(grant.until) > now) return null
  const group = ROLES.super_admin.group
  if (grant.added) {
    await kratosService.updateAdminState(grant.id, (s) => {
      const current = Array.isArray(s.metadataAdmin.groups) ? (s.metadataAdmin.groups as string[]) : []
      return { ...s, metadataAdmin: { ...s.metadataAdmin, groups: current.filter((g) => g !== group) } }
    })
    await removeFromGroup(grant.id, group)
  }
  await redis.del(BREAK_GLASS_KEY)
  breakGlassUses.labels('expired').inc()
  logger.warn({ grant }, 'break-glass grant expired: the super_admin membership it added was removed')
  auditEventService.emit({
    type: 'rbac.break_glass_expired', target: { type: 'user', id: grant.id }, result: 'applied',
    reason: grant.reason, severity: 'high', actor: { email: 'break-glass', type: 'system' }, source: 'jinbe-api',
    details: { at: grant.at, until: grant.until, removed: grant.added },
  }).catch(() => {})
  invalidateAuthz()
  void opalPublisher.refreshAll('break-glass-expired')
  return grant
}

let sweeper: ReturnType<typeof setInterval> | null = null

/** Every minute in the server: the deadline holds even if nobody remembers it. */
export function startBreakGlassSweeper(logger: Pick<Logger, 'warn'>): void {
  if (sweeper) return
  sweeper = setInterval(() => void sweepBreakGlass(logger).catch(() => {}), 60_000)
  sweeper.unref?.()
}
