/**
 * Jinbe bootstrap CLI.
 *
 * Run as a Helm post-install/post-upgrade Job. Seeds RBAC defaults,
 * upserts Oathkeeper rules, merges built-in route_map, creates the
 * default admin identity (first run only), and writes a marker into
 * Redis so subsequent runs short-circuit.
 *
 * Exit codes:
 *   0 — success (including no-op and lock-held paths)
 *   1 — invalid environment / required first-run config missing
 *   2 — dependency timeout (Redis or Kratos)
 *   3 — bootstrap failed (after passing env + dependency checks)
 *   4 — schema downgrade detected
 *   5 — marker corruption
 *
 * `--plan [--out DIR] [--opa]` (authz v2, wave V0): READ-ONLY. Takes no lock, writes no marker and
 * no RBAC key (only the shared identity-directory cache may refresh); reads the live v1 RBAC state with jinbe's own credentials and writes the v2 review
 * list (plan.json, plan.md) to DIR (default /tmp/jinbe-authz-plan). `--opa` also checks every listed
 * person's v1 platform permissions against OPA. Run it inside the jinbe pod:
 *   kubectl exec deploy/jinbe -- node dist/cli/bootstrap.js --plan --out /tmp/plan --opa
 *   kubectl cp <pod>:/tmp/plan ./plan
 */

import pino from 'pino'
import { env } from '../config/env.js'
import { redisClientService } from '../services/redis-client.service.js'
import { runBootstrap, SchemaDowngradeError } from '../bootstrap/index.js'
import { readMarker, MarkerCorruptError } from '../bootstrap/marker.js'
import { waitForRedis, waitForKratos, DependencyTimeoutError } from '../bootstrap/wait-deps.js'
import { buildBuiltInRules, OPTIONAL_BUILT_IN_RULE_IDS } from '../bootstrap/build-rules.js'
import { runPlan } from '../authz-v2/plan/run.js'
import type { BootstrapConfig } from '../bootstrap/types.js'

const EXIT = {
  SUCCESS: 0,
  INVALID_ENV: 1,
  DEPENDENCY_TIMEOUT: 2,
  BOOTSTRAP_FAILED: 3,
  SCHEMA_DOWNGRADE: 4,
  MARKER_CORRUPT: 5,
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

/** `--plan`: the read-only v2 review list. */
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
    await runPlan({ logger, outDir: argValue('--out') ?? '/tmp/jinbe-authz-plan', opa: process.argv.includes('--opa'), docs: env.ENABLE_SWAGGER, builtInRuleIds })
    return EXIT.SUCCESS
  } catch (err) {
    logger.error({ err: (err as Error).message, stack: (err as Error).stack }, 'plan failed')
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
    })
    logger.info({ outcome: result.outcome }, 'Bootstrap CLI finished')
    return EXIT.SUCCESS
  } catch (err) {
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
