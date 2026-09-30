import type { FastifyRequest } from 'fastify'
import { sitesConfig } from '../sites/config.js'
import { getRedisClient } from '../services/redis-client.service.js'

/**
 * What a delegated caller (an MCP key acting as its holder) may WRITE, beyond "its scopes cover the
 * route" (middleware/delegation-gate.ts). Owner decision, 2026-09-29: "MCP can do anything the user
 * can do, fast; it must never delete anything (deletes are by hand)".
 *
 *   NEVER   any DELETE, zones and the gateway configuration — rules in the gate's fixed list, beside
 *           second-factor resets, key minting, approvals and the access model;
 *   BUDGET  60 writes a minute per (holder, client): a bulk plan counts as one call, so mapping 200
 *           routes is one write here;
 *   PROD    with SITES_PRODUCTION on, a delegated caller does not publish directly: apply and rollback
 *           answer `use_apply_request`, and the existing apply request (POST /sites/:name/requests,
 *           approved by a person in kuma, four-eyes as configured) is the way.
 */

type Rule = { method: string; pattern: RegExp }

/** What a delegated caller may not do directly in production: publishing goes through a request. */
const PRODUCTION_PUBLISH: readonly Rule[] = [
  { method: 'POST', pattern: /^\/api\/admin\/sites\/:name\/(apply|rollback)$/ },
]

/** Why a delegated caller must take another way in production, or null. */
export function productionRedirect(method: string, pattern: string): string | null {
  if (!sitesConfig().SITES_PRODUCTION) return null
  return PRODUCTION_PUBLISH.some((r) => r.method === method && r.pattern.test(pattern)) ? 'use_apply_request' : null
}

/** Writes per minute for one (holder, client). */
export const DELEGATED_WRITES_PER_MINUTE = 60
const WINDOW_S = 60

/**
 * Counts one delegated write; the seconds to wait when over budget, else null. It is a flood brake,
 * not an authorization: with the counter unreachable the write goes on (logged) — the scopes, the
 * route guards and the catalogue still decide.
 */
export async function delegatedWriteBudget(request: FastifyRequest): Promise<number | null> {
  const uc = request.userContext
  const key = `jinbe:delegated-writes:${uc?.id ?? 'unknown'}:${uc?.delegation?.clientId ?? 'unknown'}`
  try {
    const redis = getRedisClient()
    const n = await redis.incr(key)
    if (n === 1) await redis.expire(key, WINDOW_S)
    if (n <= DELEGATED_WRITES_PER_MINUTE) return null
    const ttl = await redis.ttl(key)
    return ttl > 0 ? ttl : WINDOW_S
  } catch (err) {
    request.log?.warn({ reason: (err as Error).message }, 'delegated write budget unavailable (write allowed)')
    return null
  }
}
