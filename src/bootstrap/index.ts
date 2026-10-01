import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { buildBuiltInRules } from './build-rules.js'
import { upsertBuiltInRules } from './upsert-rules.js'
import { migrateSecondFactorFlags } from '../second-factor/settings.js'
import { seedDefaultAdmin } from './seed-admin.js'
import { readMarker, writeMarker, clearMarker, type BootstrapMarker } from './marker.js'
import { acquireLock, releaseLock, generateHolderId } from './lock.js'
import { canonicalHash } from './hash.js'
import { GENERATED_ROUTE_MAP } from '../policy/route-map.generated.js'
import { convergeJinbe } from './converge.js'
import { applyModel } from './apply.js'
import { sweepBreakGlass } from './break-glass.js'
import type { RunBootstrapOptions, BootstrapLogger } from './types.js'
import { backupStore } from '../services/backup-store.service.js'
import { rbacBundleService } from '../services/rbac-bundle.service.js'

/**
 * Bootstrap schema version. Bump when a built-in seed needs a one-time targeted
 * re-run that goes beyond the natural idempotency of upsert/converge operations.
 *
 * v1–v7: the previous authorization model (global roles, `*`, the org roster, org grants, the org →
 *     service map, kuma as a service, additive route-map merge).
 * v8: the model in place (authz-v2-design): exact permissions, no wildcard, platform and org scopes,
 *     org roles stored by jinbe, the generated super_admin. Reaching it WIPES the stored RBAC and
 *     reseeds it from code and the applied sites (bootstrap/apply.ts) — only with the reviewed plan's
 *     hash (`--apply --expect`, or JINBE_RBAC_APPLY_EXPECT for the release's own bootstrap run), after
 *     a mandatory store snapshot.
 */
export const SCHEMA_VERSION = 8

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
 *   marker absent                            → apply the model (nothing to review), write marker
 *   marker.schemaVersion > SCHEMA_VERSION    → throw SchemaDowngradeError
 *   marker.schemaVersion < SCHEMA_VERSION    → the reviewed plan's hash is required (expectPlan):
 *                                              snapshot, wipe, reseed, write marker — or throw
 *                                              MigrationNotApprovedError and change nothing
 *   marker present, schemaVersion matches:
 *     built-in gateway rules changed        → re-upsert them, update hash
 *     always                                → converge what jinbe owns, expire break-glass
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
    const builtInRules = buildBuiltInRules({ domains: config.domains, urls: config.urls, signInGate: config.signInGate, mcp: config.mcp, mcpOAuthIssuer: config.mcpOAuthIssuer })
    const currentBuiltInsHash = {
      rules: canonicalHash(builtInRules),
      routeMap: canonicalHash(GENERATED_ROUTE_MAP),
    }

    if (existing && existing.schemaVersion > SCHEMA_VERSION) {
      throw new SchemaDowngradeError(existing.schemaVersion, SCHEMA_VERSION)
    }

    let outcome: BootstrapOutcome
    const snapshotDir = opts.snapshotDir ?? '/tmp/jinbe-snapshots'

    if (!existing) {
      outcome = 'first-run'
      logger.info({ schemaVersion: SCHEMA_VERSION }, 'First bootstrap run — seeding the model from code')
      await applyModel({ logger, expect: null, firstRun: true, builtInRules, gitSha: opts.gitSha, snapshotDir })
      await maybeRestoreFromBackup(logger)
      if (config.admin) await seedDefaultAdmin(config.admin, logger)
    } else if (existing.schemaVersion < SCHEMA_VERSION) {
      if (!opts.expectPlan) throw new MigrationNotApprovedError(existing.schemaVersion)
      outcome = 'schema-upgrade'
      logger.warn({ from: existing.schemaVersion, to: SCHEMA_VERSION, expect: opts.expectPlan }, 'Schema upgrade — applying the reviewed plan (wipe and reseed)')
      const result = await applyModel({
        logger, expect: opts.expectPlan, firstRun: false, builtInRules, gitSha: opts.gitSha, snapshotDir,
        snapshotDirDurable: opts.snapshotDirDurable, allowEphemeralSnapshot: opts.allowEphemeralSnapshot,
      })
      logger.info({ ...result }, 'Model applied')
    } else if (
      existing.builtInsHash.rules !== currentBuiltInsHash.rules ||
      existing.builtInsHash.routeMap !== currentBuiltInsHash.routeMap
    ) {
      outcome = 'builtins-drift'
      logger.info('Built-in content changed — re-upserting rules and converging the route map')
      await upsertBuiltInRules(builtInRules, logger)
      await convergeJinbe(logger)
    } else {
      outcome = 'no-op'
      logger.info({ schemaVersion: existing.schemaVersion }, 'Bootstrap marker present and current — converging what jinbe owns')
      await convergeJinbe(logger)
      await pinSecondFactorDefaults(logger)
      await sweepBreakGlass(logger).catch(() => null)
      return { outcome, marker: existing }
    }
    await pinSecondFactorDefaults(logger)
    await sweepBreakGlass(logger).catch(() => null)

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
 * First init only (marker absent), after the model is seeded: when backup is enabled and a
 * `latest.json` exists in S3, restore the RBAC bundle from it (what code owns is skipped by the
 * importer). A failed restore leaves the freshly seeded model rather than blocking first init.
 */
async function maybeRestoreFromBackup(logger: BootstrapLogger): Promise<void> {
  if (!backupStore.enabled()) return
  try {
    const latest = await backupStore.getLatest()
    if (!latest) {
      logger.info('Backup enabled but no latest.json in S3 — keeping the seeded model')
      return
    }
    logger.info('First init: restoring RBAC from the latest backup')
    await rbacBundleService.import(latest)
  } catch (e) {
    logger.warn({ err: String(e) }, 'Backup restore failed — keeping the seeded model')
  }
}

/**
 * Every group's "Members must use 2FA" switch written down (second-factor/settings.ts): its default
 * where none is stored, stored values kept. After the staff groups exist. Not fatal — an unpinned
 * group still gets the same default at read time.
 */
async function pinSecondFactorDefaults(logger: BootstrapLogger): Promise<void> {
  try {
    await migrateSecondFactorFlags(logger)
  } catch (e) {
    logger.warn({ err: String(e) }, 'second factor: could not pin the per-group defaults; they still apply at read time')
  }
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

/** An install the previous model wrote, and no reviewed plan to move it: nothing is changed. */
export class MigrationNotApprovedError extends Error {
  constructor(public readonly markerVersion: number) {
    super(
      `The stored RBAC was written by the previous model (schema ${markerVersion}). Run --plan, review it, then ` +
        '--apply --expect <planHash> (or set JINBE_RBAC_APPLY_EXPECT to the reviewed hash). Nothing was changed.',
    )
    this.name = 'MigrationNotApprovedError'
  }
}

export type { RunBootstrapOptions, BootstrapLogger } from './types.js'
export { MARKER_KEY, type BootstrapMarker } from './marker.js'
