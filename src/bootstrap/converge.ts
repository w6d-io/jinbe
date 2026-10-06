import { getRedisClient } from '../services/redis-client.service.js'
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
  if (result.created.length || result.updated.length || result.removed?.length) {
    logger.info({ created: result.created, updated: result.updated, removed: result.removed ?? [] }, 'RBAC owned by jinbe written')
  }
  return result
}
