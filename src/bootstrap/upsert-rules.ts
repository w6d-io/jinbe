import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { OPTIONAL_BUILT_IN_RULE_IDS } from './build-rules.js'
import type { BootstrapLogger, OathkeeperRule } from './types.js'

/**
 * Upsert built-in Oathkeeper rules into Redis.
 *
 * Built-in rule IDs (from buildBuiltInRules) overwrite any existing rule
 * with the same ID; optional built-in ids not emitted this time are removed. Custom rules (any rule with an ID not in the built-in
 * set) are preserved verbatim.
 *
 * The combined list is written atomically to `rbac:oathkeeper:rules`.
 */
export async function upsertBuiltInRules(
  builtIn: OathkeeperRule[],
  logger: BootstrapLogger,
): Promise<{ builtIn: number; custom: number }> {
  const existing = (await redisRbacRepository.getAccessRules()) ?? []
  // An optional built-in the builder no longer emits (the sign-in gate turned off) goes too: kept,
  // it would overlap the rule that replaced it and Oathkeeper would refuse the match.
  const builtInIds = new Set([...builtIn.map((r) => r.id), ...OPTIONAL_BUILT_IN_RULE_IDS])
  const custom = existing.filter((r) => !builtInIds.has(r.id))
  const merged = [...builtIn, ...custom]
  await redisRbacRepository.setAccessRules(merged)
  logger.info({ builtIn: builtIn.length, custom: custom.length }, 'Access rules upserted in Redis')
  return { builtIn: builtIn.length, custom: custom.length }
}
