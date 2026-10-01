/**
 * Jinbe bootstrap CLI.
 *
 * Run as a Helm post-install/post-upgrade Job: converges what jinbe owns in the RBAC store (its roles,
 * route map, org roles, staff groups), upserts the built-in Oathkeeper rules, creates the default
 * admin identity (first run only) and writes a marker into Redis.
 *
 * Exit codes:
 *   0 — success (including no-op and lock-held paths)
 *   1 — invalid environment / required first-run config missing
 *   2 — dependency timeout (Redis or Kratos)
 *   3 — bootstrap failed (after passing env + dependency checks)
 *   4 — schema downgrade detected
 *   5 — marker corruption
 *   6 — the stored RBAC is the previous model's and no reviewed plan approves moving it (nothing changed)
 *   7 — break-glass refused
 *
 * Commands, run inside the jinbe pod (`kubectl exec deploy/jinbe -- node dist/cli/bootstrap.js …`):
 *
 *   --plan [--out DIR] [--opa]          READ-ONLY review list (plan.json, plan.md, planHash): today's
 *                                       state, every rule after the apply, each person's gains and
 *                                       losses, orphans, the migration map. `--opa` checks today's
 *                                       platform permissions against OPA. No lock, no RBAC write.
 *   --apply --expect HASH [--out DIR]   the reviewed move: mandatory store snapshot (file + S3), wipe,
 *                                       reseed from code and the applied sites; refused unless the
 *                                       live state still gives HASH.
 *   --restore-snapshot FILE|S3KEY       puts the store back exactly as a snapshot holds it (rollback:
 *                                       then redeploy the previous release).
 *   --break-glass --email A --reason R [--minutes N] [--dry-run]
 *                                       the one emergency path (bootstrap/break-glass.ts); the offline
 *                                       code is read from stdin.
 */

import pino from 'pino'
import { env } from '../config/env.js'
import { redisClientService } from '../services/redis-client.service.js'
import { runBootstrap, SchemaDowngradeError, MigrationNotApprovedError, SCHEMA_VERSION } from '../bootstrap/index.js'
import { readMarker, MarkerCorruptError } from '../bootstrap/marker.js'
import { waitForRedis, waitForKratos, DependencyTimeoutError } from '../bootstrap/wait-deps.js'
import { buildBuiltInRules, OPTIONAL_BUILT_IN_RULE_IDS } from '../bootstrap/build-rules.js'
import { runPlan } from '../bootstrap/plan/run.js'
import { applyModel, PlanMismatchError } from '../bootstrap/apply.js'
import { loadSnapshot, restoreSnapshot } from '../bootstrap/snapshot.js'
import { breakGlass, BreakGlassError } from '../bootstrap/break-glass.js'
import { acquireLock, releaseLock, generateHolderId } from '../bootstrap/lock.js'
import { writeMarker } from '../bootstrap/marker.js'
import { canonicalHash } from '../bootstrap/hash.js'
import { GENERATED_ROUTE_MAP } from '../policy/route-map.generated.js'
import { getRedisClient } from '../services/redis-client.service.js'
import type { BootstrapConfig } from '../bootstrap/types.js'

const EXIT = {
  SUCCESS: 0,
  INVALID_ENV: 1,
  DEPENDENCY_TIMEOUT: 2,
  BOOTSTRAP_FAILED: 3,
  SCHEMA_DOWNGRADE: 4,
  MARKER_CORRUPT: 5,
  NOT_APPROVED: 6,
  BREAK_GLASS_REFUSED: 7,
} as const

function argValue(name: string): string | undefined {
  const i = process.argv.indexOf(name)
  return i >= 0 ? process.argv[i + 1] : undefined
}

/** What the orchestrator and the plan are configured with, from the environment. */
function configFromEnv(): BootstrapConfig {
  return {
    domains: {
      auth: env.AUTH_DOMAIN!,
      app: env.APP_DOMAIN!,
      api: env.API_DOMAIN || env.APP_DOMAIN!,
    },
    urls: {
      kratosPublic: env.KRATOS_PUBLIC_URL,
      kratosAdmin: env.KRATOS_ADMIN_URL,
      loginUi: env.LOGIN_UI_URL!,
      adminUi: env.ADMIN_UI_URL!,
      jinbeInternal: env.JINBE_INTERNAL_URL,
    },
    signInGate: env.SIGN_IN_GATE_ENABLED,
    mcp: env.MCP_PUBLIC_URL && env.MCP_UPSTREAM_URL ? { publicUrl: env.MCP_PUBLIC_URL, upstream: env.MCP_UPSTREAM_URL } : null,
    mcpOAuthIssuer: env.MCP_OAUTH_ISSUER || null,
    admin: env.ADMIN_EMAIL && env.ADMIN_PASSWORD ? { email: env.ADMIN_EMAIL, password: env.ADMIN_PASSWORD, name: env.ADMIN_NAME } : null,
  }
}

/** `--plan`: the read-only review list. */
async function plan(logger: pino.Logger): Promise<number> {
  try {
    await waitForRedis({ logger })
  } catch (err) {
    if (err instanceof DependencyTimeoutError) return EXIT.DEPENDENCY_TIMEOUT
    throw err
  }
  const config = configFromEnv()
  let builtInRuleIds = new Set<string>(OPTIONAL_BUILT_IN_RULE_IDS)
  try {
    const rules = buildBuiltInRules({ domains: config.domains, urls: config.urls, signInGate: config.signInGate, mcp: config.mcp, mcpOAuthIssuer: config.mcpOAuthIssuer })
    builtInRuleIds = new Set([...rules.map((r) => r.id), ...OPTIONAL_BUILT_IN_RULE_IDS])
  } catch (err) {
    logger.warn({ err: (err as Error).message }, 'plan: built-in rules could not be built from the environment — every rule id is listed')
  }
  try {
    await runPlan({ logger, outDir: argValue('--out') ?? '/tmp/jinbe-authz-plan', opa: process.argv.includes('--opa'), builtInRuleIds })
    return EXIT.SUCCESS
  } catch (err) {
    logger.error({ err: (err as Error).message, stack: (err as Error).stack }, 'plan failed')
    return EXIT.BOOTSTRAP_FAILED
  }
}

/** `--apply --expect HASH`: the reviewed move, under the bootstrap lock, marker written last. */
async function apply(logger: pino.Logger): Promise<number> {
  const expect = argValue('--expect')
  if (!expect) {
    logger.error('--apply needs --expect <planHash> from a reviewed --plan')
    return EXIT.NOT_APPROVED
  }
  try {
    await waitForRedis({ logger })
    await waitForKratos({ url: env.KRATOS_ADMIN_URL, token: env.KRATOS_ADMIN_TOKEN, logger })
  } catch (err) {
    if (err instanceof DependencyTimeoutError) return EXIT.DEPENDENCY_TIMEOUT
    throw err
  }
  const holder = generateHolderId()
  if (!(await acquireLock(holder))) {
    logger.error('The bootstrap lock is held by another runner — retry when it is done')
    return EXIT.BOOTSTRAP_FAILED
  }
  try {
    const config = configFromEnv()
    const builtInRules = buildBuiltInRules({ domains: config.domains, urls: config.urls, signInGate: config.signInGate, mcp: config.mcp, mcpOAuthIssuer: config.mcpOAuthIssuer })
    const previous = await readMarker()
    const result = await applyModel({
      logger, expect, firstRun: false, builtInRules, gitSha: env.COMMIT_SHA || 'unknown',
      snapshotDir: env.JINBE_SNAPSHOT_DIR, planDir: argValue('--out'),
    })
    const now = new Date().toISOString()
    await writeMarker({
      version: env.APP_VERSION || 'unknown',
      schemaVersion: SCHEMA_VERSION,
      gitSha: env.COMMIT_SHA || 'unknown',
      bootstrappedAt: previous?.bootstrappedAt ?? now,
      lastUpgradeAt: now,
      previousSchemaVersion: previous?.schemaVersion ?? null,
      manualMigration: previous?.manualMigration,
      migrations: [...(previous?.migrations ?? []), { from: previous?.schemaVersion ?? null, to: SCHEMA_VERSION, appliedAt: now, gitSha: env.COMMIT_SHA || 'unknown' }],
      builtInsHash: { rules: canonicalHash(builtInRules), routeMap: canonicalHash(GENERATED_ROUTE_MAP) },
    })
    logger.info({ ...result }, 'Applied. Rollback: --restore-snapshot <snapshot>, then redeploy the previous release')
    return EXIT.SUCCESS
  } catch (err) {
    if (err instanceof PlanMismatchError) {
      logger.error({ actual: err.actual, expected: err.expected }, err.message)
      return EXIT.NOT_APPROVED
    }
    logger.error({ err: (err as Error).message, stack: (err as Error).stack }, 'apply failed')
    return EXIT.BOOTSTRAP_FAILED
  } finally {
    await releaseLock(holder).catch(() => undefined)
  }
}

/** `--restore-snapshot FILE|S3KEY`: the store exactly as the snapshot holds it. */
async function restore(logger: pino.Logger): Promise<number> {
  const from = argValue('--restore-snapshot')
  if (!from) {
    logger.error('--restore-snapshot needs a file path or an S3 key')
    return EXIT.INVALID_ENV
  }
  try {
    await waitForRedis({ logger })
    const snapshot = await loadSnapshot(from)
    const result = await restoreSnapshot(getRedisClient(), snapshot)
    logger.warn({ from, takenAt: snapshot.takenAt, ...result }, 'RBAC store restored from the snapshot — now redeploy the release that wrote it')
    return EXIT.SUCCESS
  } catch (err) {
    logger.error({ err: (err as Error).message }, 'restore failed')
    return EXIT.BOOTSTRAP_FAILED
  }
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8').trim()
}

/** `--break-glass`: restore one super_admin membership, time-bounded and alerted. */
async function breakGlassCommand(logger: pino.Logger): Promise<number> {
  try {
    await waitForRedis({ logger })
    const result = await breakGlass({
      email: argValue('--email') ?? '',
      reason: argValue('--reason') ?? '',
      code: await readStdin(),
      expectedSha256: env.JINBE_BREAK_GLASS_CODE_SHA256,
      minutes: Number(argValue('--minutes') ?? '60'),
      dryRun: process.argv.includes('--dry-run'),
      logger,
    })
    logger.warn({ result }, process.argv.includes('--dry-run') ? 'break-glass dry run: everything is in place' : 'break-glass applied')
    return EXIT.SUCCESS
  } catch (err) {
    if (err instanceof BreakGlassError) {
      logger.error({ err: err.message }, 'break-glass refused')
      return EXIT.BREAK_GLASS_REFUSED
    }
    logger.error({ err: (err as Error).message }, 'break-glass failed')
    return EXIT.BOOTSTRAP_FAILED
  }
}

async function main(): Promise<number> {
  const logger = pino({
    level: env.LOG_LEVEL,
    base: {
      service: 'jinbe-bootstrap',
      release: env.RELEASE_NAME,
      gitSha: env.COMMIT_SHA,
    },
  })

  if (process.argv.includes('--plan')) return plan(logger)
  if (process.argv.includes('--apply')) return apply(logger)
  if (process.argv.includes('--restore-snapshot')) return restore(logger)
  if (process.argv.includes('--break-glass')) return breakGlassCommand(logger)

  logger.info({ schemaTarget: 1 }, 'Bootstrap CLI starting')

  // Required runtime env (these are zod-validated at import; we just check the
  // bootstrap-required values here for explicit early failure with a clear msg).
  const required = {
    REDIS_URL: env.REDIS_URL,
    KRATOS_ADMIN_URL: env.KRATOS_ADMIN_URL,
    JINBE_INTERNAL_URL: env.JINBE_INTERNAL_URL,
    AUTH_DOMAIN: env.AUTH_DOMAIN,
    APP_DOMAIN: env.APP_DOMAIN,
    LOGIN_UI_URL: env.LOGIN_UI_URL,
    ADMIN_UI_URL: env.ADMIN_UI_URL,
  }
  const missing = Object.entries(required).filter(([, v]) => !v).map(([k]) => k)
  if (missing.length > 0) {
    logger.error({ missing }, 'Required environment variables missing')
    return EXIT.INVALID_ENV
  }

  // Wait for dependencies before any work.
  try {
    await waitForRedis({ logger })
    await waitForKratos({ url: env.KRATOS_ADMIN_URL, token: env.KRATOS_ADMIN_TOKEN, logger })
  } catch (err) {
    if (err instanceof DependencyTimeoutError) {
      logger.error({ dependency: err.dependency, attempts: err.attempts }, 'Dependency timeout')
      return EXIT.DEPENDENCY_TIMEOUT
    }
    throw err
  }

  // First-run check: marker absent + admin credentials missing → exit early.
  let existingMarker
  try {
    existingMarker = await readMarker()
  } catch (err) {
    if (err instanceof MarkerCorruptError) {
      logger.error({ raw: err.raw }, 'Bootstrap marker corruption — refusing to proceed')
      return EXIT.MARKER_CORRUPT
    }
    throw err
  }

  const isFirstRun = existingMarker === null
  if (isFirstRun && (!env.ADMIN_EMAIL || !env.ADMIN_PASSWORD)) {
    logger.error(
      'First bootstrap requires ADMIN_EMAIL and ADMIN_PASSWORD. ' +
        'Provide both via the Helm values (Vault-injected for ADMIN_PASSWORD recommended).',
    )
    return EXIT.INVALID_ENV
  }

  // Reset path guard: requires DANGEROUS_RESET=true AND RESET_CONFIRM matching git SHA.
  let force = false
  if (env.JINBE_BOOTSTRAP_DANGEROUS_RESET) {
    if (env.JINBE_BOOTSTRAP_RESET_CONFIRM !== env.COMMIT_SHA) {
      logger.error(
        { expected: env.COMMIT_SHA, got: env.JINBE_BOOTSTRAP_RESET_CONFIRM },
        'JINBE_BOOTSTRAP_DANGEROUS_RESET set but JINBE_BOOTSTRAP_RESET_CONFIRM does not match running image gitSha — refusing reset',
      )
      return EXIT.INVALID_ENV
    }
    logger.warn(
      { gitSha: env.COMMIT_SHA, release: env.RELEASE_NAME },
      'CRITICAL: bootstrap reset requested with both guards present — clearing marker',
    )
    force = true
  }

  try {
    const result = await runBootstrap({
      logger,
      gitSha: env.COMMIT_SHA || 'unknown',
      version: env.APP_VERSION || 'unknown',
      force,
      config: configFromEnv(),
      expectPlan: env.JINBE_RBAC_APPLY_EXPECT ?? null,
      snapshotDir: env.JINBE_SNAPSHOT_DIR,
    })
    logger.info({ outcome: result.outcome }, 'Bootstrap CLI finished')
    return EXIT.SUCCESS
  } catch (err) {
    if (err instanceof MigrationNotApprovedError || err instanceof PlanMismatchError) {
      logger.error({ err: err.message }, 'The stored RBAC was not moved: review --plan, then --apply --expect <planHash>')
      return EXIT.NOT_APPROVED
    }
    if (err instanceof SchemaDowngradeError) {
      logger.error(
        { markerVersion: err.markerVersion, codeVersion: err.codeVersion },
        'Schema downgrade — bootstrap aborted',
      )
      return EXIT.SCHEMA_DOWNGRADE
    }
    logger.error({ err: (err as Error).message, stack: (err as Error).stack }, 'Bootstrap failed')
    return EXIT.BOOTSTRAP_FAILED
  }
}

void main()
  .then((code) => {
    redisClientService.disconnect().finally(() => process.exit(code))
  })
  .catch((err) => {
    console.error('[bootstrap] uncaught:', err)
    redisClientService.disconnect().finally(() => process.exit(EXIT.BOOTSTRAP_FAILED))
  })
