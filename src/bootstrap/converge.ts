import { getRedisClient } from '../services/redis-client.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { forgetGroupMembers, pruneRetiredGroups } from '../services/group-cascade.js'
import { auditEventService } from '../services/audit-event.service.js'
import { rbacOwnedDrift } from '../telemetry/metrics.js'
import { env } from '../config/env.js'
import { JINBE } from '../policy/roles.js'
import { convergeOwned, jinbeOwned, type ConvergeResult } from './owned-keys.js'

interface Logger {
  info(obj: object, msg?: string): void
  warn(obj: object, msg?: string): void
}

/**
 * Converges what jinbe owns in the RBAC store (owned-keys.ts) — every bootstrap run, no-op boots
 * included. A hand edit is rewritten and alerted: audit `rbac.owned_drift` (high) and
 * jinbe_rbac_owned_drift_total.
 */
export async function convergeJinbe(logger: Logger): Promise<ConvergeResult> {
  const result = await convergeOwned(getRedisClient(), JINBE, jinbeOwned({ docs: env.ENABLE_SWAGGER }), JINBE)
  for (const slot of result.drifted) {
    rbacOwnedDrift.labels(slot).inc()
    auditEventService.emit({
      type: 'rbac.owned_drift', target: { type: 'rbac', id: slot },
      result: 'applied', reason: 'converged back to what code defines', severity: 'high',
      actor: { email: 'system', type: 'system' }, source: 'bootstrap',
    }).catch(() => {})
  }
  if (result.drifted.length) logger.warn({ drifted: result.drifted }, 'RBAC owned by jinbe was edited outside jinbe — converged back')
  // A staff group removed from code leaves nobody holding it; the ones retired before this existed, once.
  const retiredNow = (result.removed ?? []).filter((slot) => slot.startsWith('rbac:groups#')).map((slot) => slot.slice('rbac:groups#'.length))
  if (retiredNow.length) await forgetGroupMembers(retiredNow)
  await pruneRetiredGroups(await redisRbacRepository.getGroups()).catch((err) => logger.warn({ err }, 'retired groups not pruned from their members yet'))
  if (result.created.length || result.updated.length || result.removed?.length) {
    logger.info({ created: result.created, updated: result.updated, removed: result.removed ?? [] }, 'RBAC owned by jinbe written')
  }
  return result
}
