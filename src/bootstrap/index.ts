import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { seedRbacDefaults } from './seed-rbac.js'
import { buildBuiltInRules } from './build-rules.js'
import { upsertBuiltInRules } from './upsert-rules.js'
import { JINBE_BUILT_IN_ROUTES } from './build-route-map.js'
import { mergeJinbeRouteMap } from './merge-route-map.js'
import { seedKumaService } from './seed-kuma.js'
import { seedDefaultAdmin } from './seed-admin.js'
import {
  readMarker,
  writeMarker,
  clearMarker,
  type BootstrapMarker,
} from './marker.js'
import { acquireLock, releaseLock, generateHolderId } from './lock.js'
import { canonicalHash } from './hash.js'
import type { RunBootstrapOptions, BootstrapLogger, BootstrapConfig } from './types.js'

/**
 * Bootstrap schema version. Bump when a built-in seed needs a one-time targeted
 * re-run that goes beyond the natural idempotency of upsert/merge operations.
 *
 * v1: extracted bootstrap from server.ts inline. Behavior matches pre-extraction.
 */
export const SCHEMA_VERSION = 1

export type BootstrapOutcome =
  | 'first-run'
  | 'no-op'
  | 'builtins-drift'
  | 'schema-upgrade'
  | 'reset'
  | 'lock-held'
  | 'schema-downgrade'

export interface RunBootstrapResult {
  outcome: BootstrapOutcome
  marker?: BootstrapMarker
}

/**
 * Run the bootstrap orchestrator.
 *
 * Decision matrix:
 *   marker absent                            → full first-run seed, write marker
 *   marker.schemaVersion > SCHEMA_VERSION    → throw SchemaDowngradeError
 *   marker.schemaVersion < SCHEMA_VERSION    → run upsert/merge, record migration, write marker
 *   marker present, schemaVersion matches:
 *     builtInsHash differs from current     → re-upsert rules + route_map, update hash
 *     builtInsHash matches                  → no-op
 *
 * Concurrency: takes a Redis SETNX lock. If the lock is held, returns
 * { outcome: 'lock-held' } without throwing — the caller treats that as success
 * (another runner is doing the work).
 *
 * Reset path: if `force` is set in opts, the marker is cleared before
 * running and a fresh first-run seed is performed.
 */
export async function runBootstrap(opts: RunBootstrapOptions): Promise<RunBootstrapResult> {
  const { logger, config, force = false } = opts
  const holder = generateHolderId()
  const lockId = await acquireLock(holder)
  if (!lockId) {
    logger.info('Bootstrap lock held by another runner — exiting as no-op')
    return { outcome: 'lock-held' }
  }

  try {
    if (force) {
      logger.warn({ confirmedFor: opts.gitSha }, 'Force reset requested — clearing marker')
      await clearMarker()
    }

    const existing = await readMarker()
    const builtInRules = buildBuiltInRules({ domains: config.domains, urls: config.urls })
    const currentBuiltInsHash = {
      rules: canonicalHash(builtInRules),
      routeMap: canonicalHash(JINBE_BUILT_IN_ROUTES),
    }

    if (existing && existing.schemaVersion > SCHEMA_VERSION) {
      throw new SchemaDowngradeError(existing.schemaVersion, SCHEMA_VERSION)
    }

    let outcome: BootstrapOutcome

    if (!existing) {
      outcome = 'first-run'
      logger.info({ schemaVersion: SCHEMA_VERSION }, 'First bootstrap run — seeding all defaults')
      await runFullBootstrap(config, logger)
    } else if (existing.schemaVersion < SCHEMA_VERSION) {
      outcome = 'schema-upgrade'
      logger.info(
        { from: existing.schemaVersion, to: SCHEMA_VERSION },
        'Schema upgrade — re-running built-in upserts',
      )
      await runUpsertOnly(config, logger)
    } else if (
      existing.builtInsHash.rules !== currentBuiltInsHash.rules ||
      existing.builtInsHash.routeMap !== currentBuiltInsHash.routeMap
    ) {
      outcome = 'builtins-drift'
      logger.info('Built-in content drift detected — re-upserting rules and route_map')
      await runUpsertOnly(config, logger)
    } else {
      outcome = 'no-op'
      logger.info({ schemaVersion: existing.schemaVersion }, 'Bootstrap marker present and current — no work')
      return { outcome, marker: existing }
    }

    const newMarker = buildMarker({
      previous: existing,
      gitSha: opts.gitSha,
      version: opts.version,
      builtInsHash: currentBuiltInsHash,
    })
    await writeMarker(newMarker)
    await redisRbacRepository.invalidateBundleEtag()
    logger.info({ outcome, schemaVersion: SCHEMA_VERSION }, 'Bootstrap complete')
    return { outcome, marker: newMarker }
  } finally {
    await releaseLock(holder).catch(() => undefined)
  }
}

async function runFullBootstrap(config: BootstrapConfig, logger: BootstrapLogger): Promise<void> {
  await seedRbacDefaults(logger)
  await runUpsertOnly(config, logger)
  if (config.domains.app) {
    await seedKumaService(logger)
  }
  if (config.admin) {
    await seedDefaultAdmin(config.admin, logger)
  }
}

async function runUpsertOnly(config: BootstrapConfig, logger: BootstrapLogger): Promise<void> {
  const rules = buildBuiltInRules({ domains: config.domains, urls: config.urls })
  await upsertBuiltInRules(rules, logger)
  await mergeJinbeRouteMap(JINBE_BUILT_IN_ROUTES, logger)
}

function buildMarker(input: {
  previous: BootstrapMarker | null
  gitSha: string
  version: string
  builtInsHash: BootstrapMarker['builtInsHash']
}): BootstrapMarker {
  const now = new Date().toISOString()
  const { previous, gitSha, version, builtInsHash } = input
  const previousSchemaVersion = previous?.schemaVersion ?? null
  const migrations = previous?.migrations ? [...previous.migrations] : []

  if (!previous || (previousSchemaVersion !== null && previousSchemaVersion < SCHEMA_VERSION)) {
    migrations.push({
      from: previousSchemaVersion,
      to: SCHEMA_VERSION,
      appliedAt: now,
      gitSha,
    })
  }

  return {
    version,
    schemaVersion: SCHEMA_VERSION,
    gitSha,
    bootstrappedAt: previous?.bootstrappedAt ?? now,
    lastUpgradeAt: now,
    previousSchemaVersion,
    manualMigration: previous?.manualMigration,
    migrations,
    builtInsHash,
  }
}

export class SchemaDowngradeError extends Error {
  constructor(public readonly markerVersion: number, public readonly codeVersion: number) {
    super(
      `Marker schemaVersion ${markerVersion} is newer than code SCHEMA_VERSION ${codeVersion} — refusing to downgrade`,
    )
    this.name = 'SchemaDowngradeError'
  }
}

export type {
  RunBootstrapOptions,
  BootstrapConfig,
  BootstrapLogger,
} from './types.js'
export { MARKER_KEY, type BootstrapMarker } from './marker.js'
