import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { seedRbacDefaults } from './seed-rbac.js'
import { buildBuiltInRules } from './build-rules.js'
import { upsertBuiltInRules } from './upsert-rules.js'
import { JINBE_BUILT_IN_ROUTES } from './build-route-map.js'
import { mergeJinbeRouteMap } from './merge-route-map.js'
import { seedKumaService } from './seed-kuma.js'
import { seedDefaultAdmin } from './seed-admin.js'
import type { RunBootstrapOptions } from './types.js'

/**
 * Bootstrap schema version. Bump when a built-in seed needs a one-time targeted
 * re-run that goes beyond the natural idempotency of upsert/merge operations.
 *
 * v1: extracted bootstrap from server.ts inline. Behavior matches pre-extraction.
 */
export const SCHEMA_VERSION = 1

/**
 * Run all bootstrap steps.
 *
 * Phase 1: this is a behavior-preserving extraction of the inline bootstrap
 * that previously lived in server.ts. No marker, no lock, no
 * dependency waits. Those land in later phases.
 *
 * Order of operations:
 *   1. seedRbacDefaults     — initial groups/roles/services if Redis empty
 *   2. buildBuiltInRules    — pure: env → rule list
 *   3. upsertBuiltInRules   — write rules, preserve custom
 *   4. mergeJinbeRouteMap   — append new built-in routes to existing
 *   5. seedKumaService      — kuma service + propagation (only if APP_DOMAIN set)
 *   6. seedDefaultAdmin     — create Kratos admin (only if admin config provided)
 *   7. invalidateBundleEtag — signal OPA to re-fetch the bundle
 */
export async function runBootstrap(opts: RunBootstrapOptions): Promise<void> {
  const { logger, config } = opts

  await seedRbacDefaults(logger)

  const rules = buildBuiltInRules({ domains: config.domains, urls: config.urls })
  await upsertBuiltInRules(rules, logger)

  await mergeJinbeRouteMap(JINBE_BUILT_IN_ROUTES, logger)

  if (config.domains.app) {
    await seedKumaService(logger)
  }

  if (config.admin) {
    try {
      await seedDefaultAdmin(config.admin, logger)
    } catch (err) {
      logger.warn({ err, email: config.admin.email }, 'Failed to create default admin user — Kratos may not be ready yet')
    }
  }

  await redisRbacRepository.invalidateBundleEtag()
}

export type { RunBootstrapOptions, BootstrapConfig, BootstrapLogger } from './types.js'
