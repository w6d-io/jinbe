import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import type { BootstrapLogger, OathkeeperRule } from './types.js'

/**
 * Upsert built-in Oathkeeper rules into Redis.
 *
 * Built-in rule IDs (from buildBuiltInRules) overwrite any existing rule
 * with the same ID. Custom rules (any rule with an ID not in the built-in
 * set) are preserved verbatim.
 *
 * The combined list is written atomically to `rbac:oathkeeper:rules`.
 */
export async function upsertBuiltInRules(
  builtIn: OathkeeperRule[],
  logger: BootstrapLogger,
): Promise<{ builtIn: number; custom: number }> {
  const existing = (await redisRbacRepository.getAccessRules()) ?? []
  const builtInIds = new Set(builtIn.map((r) => r.id))
  const custom = existing.filter((r) => !builtInIds.has(r.id))
  const merged = [...builtIn, ...custom]
  await redisRbacRepository.setAccessRules(merged)
  logger.info({ builtIn: builtIn.length, custom: custom.length }, 'Access rules upserted in Redis')
  return { builtIn: builtIn.length, custom: custom.length }
}
