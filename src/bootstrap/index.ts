import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { backupStore } from '../services/backup-store.service.js'
import { rbacBundleService } from '../services/rbac-bundle.service.js'
import { seedRbacDefaults } from './seed-rbac.js'
import { applySystemMetadataMigration } from './migrate-system-metadata.js'
import { buildBuiltInRules } from './build-rules.js'
import { upsertBuiltInRules } from './upsert-rules.js'
import { JINBE_BUILT_IN_ROUTES } from './build-route-map.js'
import { mergeJinbeRouteMap } from './merge-route-map.js'
import { seedKumaService } from './seed-kuma.js'
import { seedDelegation } from './seed-delegation.js'
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
 * v2: system-resource metadata migration. Tags built-in groups (super_admins,
 *     admins, users, viewers, devs) and services (jinbe, kuma) with
 *     `system: true` in `rbac:groups:meta` / `rbac:services:meta` so RBAC
 *     mutation guards no longer rely on a hardcoded list inside jinbe code.
 * v3: delegated org-admin model. Seeds the `org_admin` role and the
 *     `<svc>-org-admins` / `<svc>-viewers` groups for delegated services, and
 *     adds `org:manage_users` route_map rules for the org-user endpoints so a
 *     per-service org admin can reach the centralised management API. The bump
 *     forces the additive seed to run on already-bootstrapped installs.
 * v4: add `fleet` to the delegated services. Re-runs the additive seed so
 *     fleet gets its org_admin role + fleet-org-admins/-viewers groups
 *     (idempotent — skips any already present).
 * v5: single service-agnostic `org_admins` flag group (empty binding,
 *     system:true). The bump forces the additive seed to run on
 *     already-bootstrapped installs so the flag group is created + published.
 * v6: naming norm. Seed singular `<svc>-viewer`/`<svc>-admin` groups + the
 *     `platform-admins` global-admin tier; stop seeding the retired
 *     `<svc>-org-admins`/`<svc>-viewers`. The bump re-runs the additive seed so
 *     existing installs gain the new-norm group definitions (old groups are
 *     removed by the separate data migration, not the seed).
 */
export const SCHEMA_VERSION = 6

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

/**
 * First-init only (marker absent). If backup is enabled and a `latest.json`
 * exists in S3, restore the RBAC bundle from it. The idempotent seeders that
 * follow then no-op over the restored data (but still ensure built-ins + the
 * admin identity, which the bundle does not contain). A failed restore falls
 * back to a normal default seed rather than blocking first-init.
 */
async function maybeRestoreFromBackup(logger: BootstrapLogger): Promise<void> {
  if (!backupStore.enabled()) return
  try {
    const latest = await backupStore.getLatest()
    if (!latest) {
      logger.info('Backup enabled but no latest.json in S3 — seeding defaults')
      return
    }
    logger.info('First-init: restoring RBAC from latest backup')
    await rbacBundleService.import(latest)
    logger.info({ services: latest.rbac?.services?.length ?? 0 }, 'Restored RBAC from latest backup')
  } catch (e) {
    logger.warn({ err: String(e) }, 'Backup restore failed — falling back to default seed')
  }
}

async function runFullBootstrap(config: BootstrapConfig, logger: BootstrapLogger): Promise<void> {
  await maybeRestoreFromBackup(logger)
  await seedRbacDefaults(logger)
  // Seed the kuma service BEFORE runUpsertOnly so seedDelegation (inside it)
  // sees both jinbe and kuma and can seed org_admin for each.
  if (config.domains.app) {
    await seedKumaService(logger)
  }
  await runUpsertOnly(config, logger)
  if (config.admin) {
    await seedDefaultAdmin(config.admin, logger)
  }
}

async function runUpsertOnly(config: BootstrapConfig, logger: BootstrapLogger): Promise<void> {
  const rules = buildBuiltInRules({ domains: config.domains, urls: config.urls })
  await upsertBuiltInRules(rules, logger)
  await mergeJinbeRouteMap(JINBE_BUILT_IN_ROUTES, logger)
  // Always run the metadata migration: idempotent, ensures system-protection
  // tags are present even on pre-existing installs that predate this feature.
  await applySystemMetadataMigration(logger)
  // Delegated org-admin model (org_admin role + <svc>-org-admins/-viewers
  // groups). Idempotent + additive; runs on schema upgrade and builtins-drift.
  await seedDelegation(logger)
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
