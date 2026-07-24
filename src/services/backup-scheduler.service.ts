import cron, { type ScheduledTask } from 'node-cron'
import { env } from '../config/env.js'
import { getRedisClient } from './redis-client.service.js'
import { backupStore } from './backup-store.service.js'
import { rbacBundleService } from './rbac-bundle.service.js'

type Logger = { info: (o: unknown, m?: string) => void; warn: (o: unknown, m?: string) => void; error: (o: unknown, m?: string) => void }

let task: ScheduledTask | null = null

/**
 * Scheduled RBAC-bundle backup, run BY jinbe (not an external CronJob) — jinbe
 * is already authenticated to itself and holds the S3 (IRSA) creds, so there is
 * no auth-bypass problem. Multi-replica safe: a short Redis claim key dedupes
 * the run when several replicas fire on the same cron tick.
 */
export function startBackupScheduler(logger: Logger): void {
  if (!backupStore.enabled()) return
  const schedule = env.BACKUP_SCHEDULE
  if (!cron.validate(schedule)) {
    logger.warn({ schedule }, 'BACKUP_SCHEDULE is not a valid cron expression — scheduled backup disabled')
    return
  }
  task = cron.schedule(schedule, () => void runScheduledBackup(logger), { timezone: 'UTC' })
  logger.info({ schedule }, 'Scheduled RBAC bundle backup registered')
}

export function stopBackupScheduler(): void {
  task?.stop()
  task = null
}

async function runScheduledBackup(logger: Logger): Promise<void> {
  // Dedupe across replicas: the first to claim this short window runs it. TTL is
  // small (covers the seconds of skew between replicas firing on the same tick)
  // and well under any sane backup interval, so it never blocks the next run.
  const claimed = await getRedisClient().set('rbac:backup:running', '1', 'PX', 120_000, 'NX').catch(() => null)
  if (claimed !== 'OK') return
  try {
    const bundle = await rbacBundleService.export()
    const { key } = await backupStore.putBackup(bundle)
    logger.info({ key }, 'Scheduled RBAC backup uploaded to S3')
  } catch (e) {
    logger.error({ err: String(e) }, 'Scheduled RBAC backup failed')
  }
}
