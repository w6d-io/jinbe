import cron, { type ScheduledTask } from 'node-cron'
import { getRedisClient } from './redis-client.service.js'
import { redisRecertRepository } from './redis-recert.repository.js'
import { recertService } from './recert.service.js'

type Logger = { info: (o: unknown, m?: string) => void; warn: (o: unknown, m?: string) => void; error: (o: unknown, m?: string) => void }

let task: ScheduledTask | null = null

/**
 * Recertification deadline job (spec §4.5). A single hourly scheduler scans
 * active campaigns; any whose deadline has passed is closed — pending items
 * get the campaign's onExpiry consequence (revoke → group removed via Kratos,
 * flag → marked) and the completion report is frozen.
 *
 * Multi-replica safe, same pattern as backup-scheduler: a short Redis claim
 * key dedupes replicas firing on the same tick, and closeCampaign itself runs
 * under withRedisLock(`recert:{campaignId}`).
 */
export function startRecertScheduler(logger: Logger): void {
  task = cron.schedule('0 * * * *', () => void runRecertSweep(logger), { timezone: 'UTC' })
  logger.info({ schedule: '0 * * * *' }, 'Recertification deadline scheduler registered')
}

export function stopRecertScheduler(): void {
  task?.stop()
  task = null
}

/** Exported for tests / manual runs — one sweep over active campaigns. */
export async function runRecertSweep(logger: Logger): Promise<void> {
  // Dedupe across replicas: first to claim this window runs the sweep.
  const claimed = await getRedisClient().set('rbac:recert:scheduler:running', '1', 'PX', 120_000, 'NX').catch(() => null)
  if (claimed !== 'OK') return
  const now = Date.now()
  try {
    const campaigns = await redisRecertRepository.getCampaigns()
    for (const campaign of campaigns) {
      if (campaign.status !== 'active') continue
      if (Date.parse(campaign.deadline) > now) continue
      try {
        await recertService.closeCampaign(campaign.id, null, 'deadline')
        logger.info({ campaignId: campaign.id, name: campaign.name, onExpiry: campaign.onExpiry }, 'Recert campaign closed at deadline')
      } catch (e) {
        logger.error({ campaignId: campaign.id, err: String(e) }, 'Recert deadline close failed')
      }
    }
  } catch (e) {
    logger.error({ err: String(e) }, 'Recert deadline sweep failed')
  }
}
