import type { Redis } from 'ioredis'
import { getRedisClient } from '../services/redis-client.service.js'
import { redisRbacRepository, type OathkeeperRule } from '../services/redis-rbac.repository.js'
import { persistExplicitRoles, republishAppliedSites } from '../sites/republish.js'
import { readInventory, writePlan } from './plan/run.js'
import { buildPlan } from './plan/review.js'
import { migrationOf, orgsWithoutJinbe } from './plan/migration.js'
import { EphemeralSnapshotError, snapshotDurability, takeSnapshot, storeSnapshot } from './snapshot.js'
import { convergeJinbe } from './converge.js'
import { upsertBuiltInRules } from './upsert-rules.js'
import type { BootstrapLogger } from './types.js'

/**
 * `--apply --expect <planHash>` (authz-v2-design §3.4, in place): the release's one-time move of the
 * stored RBAC onto the model code defines.
 *
 *   1. re-read the live state and rebuild the plan; refuse unless its hash is the one reviewed
 *      (nothing changed since `--plan`). A fresh install has nothing to review.
 *   2. MANDATORY snapshot of the whole store (snapshot.ts): local file, and S3 when backup is
 *      configured. Any failure here → nothing is touched.
 *   3. WIPE what the model rebuilds (WIPED_PATTERNS) — never the data about people: identities,
 *      memberships, org role assignments, settings, audit, recertification, SCIM tokens.
 *   4. RESEED: jinbe's code-owned model (converge), the built-in gateway rules, the migration map
 *      (org roles from the roster and from identities, org entitlements), every applied site's
 *      permissions republished from its intent.
 *
 * Rollback: restore the snapshot with this release (`--restore-snapshot`), then redeploy the
 * previous release. The marker is written by the caller after this returns.
 */

/** What the wipe deletes: everything the new model generates or no longer has. */
export const WIPED_PATTERNS = [
  'rbac:route_map:*', 'rbac:roles:*', 'rbac:org_roles:*', 'rbac:every_org:*', 'rbac:owned:*',
  'rbac:services', 'rbac:services:meta', 'rbac:groups', 'rbac:groups:meta',
  'rbac:org_admins', 'rbac:org_service_map', 'rbac:org_grants', 'rbac:org_sites', 'rbac:org_owner_roles',
  'rbac:oathkeeper:rules',
] as const

export class PlanMismatchError extends Error {
  constructor(public readonly actual: string, public readonly expected: string | null) {
    super(expected
      ? `The live state no longer gives the reviewed plan (expected ${expected}, now ${actual}): run --plan again and review it`
      : `No reviewed plan: run --plan, review it, then --apply --expect ${actual}`)
    this.name = 'PlanMismatchError'
  }
}

async function wipe(redis: Pick<Redis, 'scan' | 'multi'>): Promise<string[]> {
  const keys = new Set<string>()
  for (const pattern of WIPED_PATTERNS) {
    if (!pattern.includes('*')) {
      keys.add(pattern)
      continue
    }
    let cursor = '0'
    do {
      const [next, batch] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 500)
      for (const k of batch) keys.add(k)
      cursor = next
    } while (cursor !== '0')
  }
  const tx = redis.multi()
  for (const k of keys) tx.del(k)
  await tx.exec()
  return [...keys].sort()
}

export interface ApplyResult {
  planHash: string
  snapshot: { file: string; s3?: string }
  wiped: number
  orgRoles: number
  sites: { published: string[]; failed: Array<{ site: string; error: string }> }
}

export async function applyModel(opts: {
  logger: BootstrapLogger
  expect: string | null
  firstRun: boolean
  builtInRules: OathkeeperRule[]
  gitSha: string
  snapshotDir: string
  /** JINBE_SNAPSHOT_DIR_DURABLE: the operator declares the snapshot dir a persistent volume. */
  snapshotDirDurable?: boolean
  /** `--allow-ephemeral-snapshot`: apply even when no snapshot copy outlives the pod (logged loudly). */
  allowEphemeralSnapshot?: boolean
  planDir?: string
}): Promise<ApplyResult> {
  const { logger } = opts
  const builtInIds = new Set(opts.builtInRules.map((r) => r.id))
  const inv = await readInventory(logger, builtInIds)
  const plan = buildPlan(inv)
  if (opts.planDir) await writePlan(plan, opts.planDir)
  if (!opts.firstRun && plan.planHash !== opts.expect) throw new PlanMismatchError(plan.planHash, opts.expect)
  // The OAuth clients only inform the review (re-scope or revoke is the owner's call); everything
  // else the apply writes from must have been read.
  const blind = inv.unavailable.filter((u) => !u.startsWith('OAuth clients'))
  if (blind.length > 0 && !opts.firstRun) {
    throw new Error(`Refusing to apply on a partial read (${blind.join(', ')}): the plan could not see everything`)
  }

  // The rollback point must outlive the pod (a post-upgrade Job's /tmp does not). A first run has
  // nothing to roll back to.
  if (!opts.firstRun) {
    const durability = await snapshotDurability(opts.snapshotDir, opts.snapshotDirDurable === true)
    if (!durability.durable) {
      if (!opts.allowEphemeralSnapshot) throw new EphemeralSnapshotError(durability.why)
      logger.error(
        { why: durability.why, snapshotDir: opts.snapshotDir },
        '!!! --allow-ephemeral-snapshot: APPLYING WITH A ROLLBACK SNAPSHOT THAT DIES WITH THIS POD. Copy it out before the pod ends !!!',
      )
    } else {
      logger.info({ where: durability.where }, 'the rollback snapshot will outlive this pod')
    }
  }

  const redis = getRedisClient()
  const snapshot = await storeSnapshot(await takeSnapshot(redis, 'pre-apply', opts.gitSha), opts.snapshotDir)
  logger.info({ snapshot }, 'RBAC store snapshot written (the rollback point)')

  const migration = migrationOf(inv)
  // Every org keeps its own jinbe routes: an org missing from org_sites would be refused all of them.
  const lockedOut = orgsWithoutJinbe(inv, migration)
  if (lockedOut.length > 0) throw new Error(`Refusing to apply: these organisations would lose jinbe in org_sites (their org routes refused): ${lockedOut.join(', ')}`)
  const wiped = await wipe(redis)
  logger.warn({ keys: wiped.length, planHash: plan.planHash }, 'stored RBAC wiped — reseeding from code and the sites')

  await convergeJinbe(logger)
  await upsertBuiltInRules(opts.builtInRules, logger)
  for (const [org, sites] of Object.entries(migration.orgSites)) await redisRbacRepository.setOrgSites(org, sites)
  const tx = redis.multi()
  for (const [org, members] of Object.entries(migration.assignments)) tx.hset('rbac:org_assignments', org, JSON.stringify(members))
  await tx.exec()
  const sites = await republishAppliedSites({ email: 'jinbe (bootstrap apply)' })
  // The stored intents follow what was just published: a wildcard saved before they were refused
  // becomes explicit in a new version, so the first edit after the release saves.
  const madeExplicit = await persistExplicitRoles({ email: 'jinbe (bootstrap apply)' })
  if (madeExplicit.length) logger.info({ madeExplicit }, 'site roles made explicit in a new version')
  if (sites.failed.length) logger.warn({ failed: sites.failed }, 'some sites could not be republished — publish them again from their intent')
  await redisRbacRepository.invalidateBundleEtag()
  return { planHash: plan.planHash, snapshot, wiped: wiped.length, orgRoles: migration.added.length, sites }
}
