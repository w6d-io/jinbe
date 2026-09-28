import { getRedisClient } from '../services/redis-client.service.js'

/**
 * Runtime facts the Home health strip needs from EVERY replica (home-data §4 J4, J7).
 *
 * The in-process gauges (engine reports, OPAL datasource last success, rules served, audit sink
 * failures) are per replica and unscraped, so with two jinbe pods each would see half the picture.
 * These writers mirror them to Redis next to the gauge. Fire-and-forget: a metrics mirror must never
 * slow down, or fail, the call it observes — so nothing here is awaited by a caller and every error
 * is swallowed.
 */

export const ENGINES_KEY = 'home:opa:engines'
export const OPAL_KEY = 'home:opal:last_success'
export const RULES_KEY = 'home:rules:served'
export const SERVING_KEY = 'home:opa:serving'
export const auditFailuresKey = (hour: number) => `home:audit:failures:${hour}`

const HOUR_MS = 3_600_000
/** Engine reports older than the presence window are ignored on read; the hash itself ages out. */
const ENGINES_TTL_S = 600
const OPAL_TTL_S = 7 * 86_400
const RULES_TTL_S = 86_400
const FAILURES_TTL_S = 26 * 3_600

function quietly(fn: () => Promise<unknown>): void {
  try {
    void fn().catch(() => {})
  } catch {
    // A half-initialised Redis client in a test or at shutdown: nothing to mirror to.
  }
}

/** J4a: one engine's bundle report, next to engine-status.service's in-memory copy. */
export function mirrorEngineReport(id: string, revision: string | null, activatedAt: string | null, now = Date.now()): void {
  quietly(async () => {
    const redis = getRedisClient()
    await redis.hset(ENGINES_KEY, id, JSON.stringify({ revision, activatedAt, heardAt: now }))
    await redis.expire(ENGINES_KEY, ENGINES_TTL_S)
  })
}

/** J4b: a successful OPAL datasource fetch, per entry (the gauge's own bounded label). */
export function mirrorOpalFetch(entry: string, now = Date.now()): void {
  quietly(async () => {
    const redis = getRedisClient()
    await redis.hset(OPAL_KEY, entry, String(now))
    await redis.expire(OPAL_KEY, OPAL_TTL_S)
  })
}

/** J4c: the gateway rules were served (Oathkeeper polls every few seconds). */
export function mirrorRulesServed(count: number, compileErrors: number, now = Date.now()): void {
  quietly(() => getRedisClient().set(RULES_KEY, JSON.stringify({ at: now, count, compileErrors }), 'EX', RULES_TTL_S))
}

/** J7: an audit/v1 sink failure, counted per hour. */
export function mirrorAuditFailure(now = Date.now()): void {
  quietly(async () => {
    const redis = getRedisClient()
    const key = auditFailuresKey(Math.floor(now / HOUR_MS))
    await redis.incr(key)
    await redis.expire(key, FAILURES_TTL_S)
  })
}
