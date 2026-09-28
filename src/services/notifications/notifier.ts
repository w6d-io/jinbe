import { createHash } from 'node:crypto'
import { hostname } from 'node:os'
import type Redis from 'ioredis'
import { componentLogger } from '../../telemetry/logger.js'
import { notificationAttemptFailures, notificationsDeadLettered } from '../../telemetry/metrics.js'
import type { EntityEvent, Notifier } from './types.js'

const STREAM_KEY = 'notifications:outbox'
/** Events no notifier could take, with why. Kept, never dropped: an operator replays or discards them. */
export const DEAD_LETTER_KEY = 'notifications:dead'
/** Last failure reason per pending event id, so the dead letter says why and not only that. */
const FAILURES_KEY = 'notifications:failures'
/** One consumer across replicas: whoever holds this delivers and retries. */
const LOCK_KEY = 'notifications:consumer'
const GROUP = 'notification-service'
// One name for the group's consumer on every replica: only the lock holder reads, so a per-pod name
// would only leave a dead consumer in the group after each restart.
const CONSUMER = 'jinbe'
const BATCH_SIZE = 10
const PENDING_SCAN = 100
const BLOCK_MS = 5_000
const DEAD_LETTER_MAXLEN = '10000'

// Extend the lock only while it is still ours: a lock that just passed to another replica is left alone.
const EXTEND_LOCK = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('pexpire', KEYS[1], ARGV[2]) else return 0 end`
const RELEASE_LOCK = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`

interface NotificationServiceConfig {
  /** Max age in ms before an undelivered event is dead-lettered. Default: 1 hour. */
  maxAgeMs?: number
  /** Initial backoff in ms after the consumer loop itself fails (Redis down). Default: 1000. */
  initialBackoffMs?: number
  /** Max backoff in ms for the consumer loop. Default: 30000. */
  maxBackoffMs?: number
  /** Delivery attempts per event before it is dead-lettered. Default: 10. */
  maxAttempts?: number
  /** Delay ceiling after the first failed attempt; doubles per attempt. Default: 5000. */
  retryBaseMs?: number
  /** Cap on the delay between two attempts. Default: 15 minutes. */
  retryMaxMs?: number
  /** How long the consumer lock outlives a replica that stopped renewing it. Default: 60000. */
  lockTtlMs?: number
  /** This replica's token on the consumer lock. Default: `<hostname>-<pid>`. */
  holder?: string
}

const DEFAULT_MAX_AGE_MS = 60 * 60 * 1000
const DEFAULT_INITIAL_BACKOFF_MS = 1_000
const DEFAULT_MAX_BACKOFF_MS = 30_000
const DEFAULT_MAX_ATTEMPTS = 10
const DEFAULT_RETRY_BASE_MS = 5_000
const DEFAULT_RETRY_MAX_MS = 15 * 60 * 1000
const DEFAULT_LOCK_TTL_MS = 60_000

type DeadReason = 'attempts_exhausted' | 'rejected' | 'expired' | 'unreadable'

const log = () => componentLogger('notifications')

/** A stable number in [0, 1) for this key: the same event and attempt always draw the same jitter. */
function unit(key: string): number {
  return parseInt(createHash('sha1').update(key).digest('hex').slice(0, 8), 16) / 0x1_0000_0000
}

/**
 * Wait before the next attempt, after `attempt` failed ones: exponential with "equal" jitter —
 * between half and all of min(max, base × 2^(attempt-1)). Drawn from the event id, not Math.random:
 * "is it due?" is asked on every pass of the loop, and a fresh draw each time would make every
 * retry due at the shortest delay.
 */
export function retryDelayMs(id: string, attempt: number, baseMs: number, maxMs: number): number {
  const ceiling = Math.min(maxMs, baseMs * 2 ** Math.max(0, attempt - 1))
  return Math.round(ceiling / 2 + (ceiling / 2) * unit(`${id}:${attempt}`))
}

/**
 * NotificationService uses a Redis Stream as a durable outbox.
 *
 * - emit() writes events to the stream (fast, non-blocking for the caller), on every replica.
 * - start() spawns a consumer loop. Only the replica holding the consumer lock reads, delivers and
 *   retries, so N replicas do not each retry the same event.
 * - An event is ACKed once every notifier took it. A failed one stays pending and is retried after
 *   an exponential, jittered delay; after `maxAttempts` (or at once when the receiver refused it, or
 *   when it is older than `maxAgeMs`) it moves to the dead-letter stream with the reason, is counted
 *   (jinbe_notifications_dead_lettered_total) and logged once. Nothing is dropped silently.
 */
export class NotificationService {
  private redis: Redis | null = null
  private notifiers: Notifier[] = []
  private running = false
  private abortController: AbortController | null = null

  private readonly maxAgeMs: number
  private readonly initialBackoffMs: number
  private readonly maxBackoffMs: number
  private readonly maxAttempts: number
  private readonly retryBaseMs: number
  private readonly retryMaxMs: number
  private readonly lockTtlMs: number
  private readonly holder: string

  constructor(config: NotificationServiceConfig = {}) {
    this.maxAgeMs = config.maxAgeMs ?? DEFAULT_MAX_AGE_MS
    this.initialBackoffMs = config.initialBackoffMs ?? DEFAULT_INITIAL_BACKOFF_MS
    this.maxBackoffMs = config.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS
    this.maxAttempts = Math.max(1, config.maxAttempts ?? DEFAULT_MAX_ATTEMPTS)
    this.retryBaseMs = config.retryBaseMs ?? DEFAULT_RETRY_BASE_MS
    this.retryMaxMs = config.retryMaxMs ?? DEFAULT_RETRY_MAX_MS
    this.lockTtlMs = config.lockTtlMs ?? DEFAULT_LOCK_TTL_MS
    this.holder = config.holder ?? `${hostname()}-${process.pid}`
  }

  /** Set the Redis client (call before start). */
  setRedis(redis: Redis): void {
    this.redis = redis
  }

  /** Register a transport notifier. */
  register(notifier: Notifier): void {
    this.notifiers.push(notifier)
    log().info({ notifier: notifier.name }, 'notifier registered')
  }

  /** Write an event to the Redis Stream outbox. Non-blocking. */
  async emit(event: Omit<EntityEvent, 'timestamp'>): Promise<void> {
    if (!this.redis) return
    if (this.notifiers.length === 0) return

    const fullEvent: EntityEvent = {
      ...event,
      timestamp: new Date().toISOString(),
    }

    try {
      await this.redis.xadd(
        STREAM_KEY, 'MAXLEN', '~', '50000', '*',
        'data', JSON.stringify(fullEvent),
      )
    } catch (err) {
      log().error({ err, entity_type: event.entity_type, action: event.action }, 'could not write the event to the outbox')
    }
  }

  /** Start the consumer loop. Call once at boot. */
  async start(): Promise<void> {
    if (!this.redis || this.notifiers.length === 0) return
    if (this.running) return

    // Ensure consumer group exists.
    try {
      await this.redis.xgroup('CREATE', STREAM_KEY, GROUP, '0', 'MKSTREAM')
    } catch (err: any) {
      if (!err.message?.includes('BUSYGROUP')) throw err
    }

    this.running = true
    this.abortController = new AbortController()
    this.loop().catch((err) => {
      log().error({ err }, 'consumer loop crashed')
      this.running = false
    })
    log().info({ holder: this.holder, maxAttempts: this.maxAttempts }, 'consumer started')
  }

  /** Stop the consumer loop. */
  stop(): void {
    this.running = false
    this.abortController?.abort()
    // Hand over now rather than after the TTL; best effort, the TTL covers a failure here.
    this.redis?.eval(RELEASE_LOCK, 1, LOCK_KEY, this.holder).catch(() => {})
  }

  /** Pending event count for health checks. */
  async pendingCount(): Promise<number> {
    if (!this.redis) return 0
    try {
      const info = await this.redis.xpending(STREAM_KEY, GROUP)
      return (info as any)[0] as number
    } catch {
      return 0
    }
  }

  // --- internal ---

  private async loop(): Promise<void> {
    let backoff = 0

    while (this.running) {
      try {
        if (!(await this.holdLock())) {
          // Another replica delivers. Stay ready to take over when its lock lapses.
          await this.sleep(BLOCK_MS)
          continue
        }

        await this.retryDue()

        // Read new messages.
        const results = await this.redis!.xreadgroup(
          'GROUP', GROUP, CONSUMER,
          'COUNT', String(BATCH_SIZE),
          'BLOCK', String(BLOCK_MS),
          'STREAMS', STREAM_KEY, '>'
        ) as [string, [string, string[]][]][] | null

        backoff = 0
        if (!results || results.length === 0) continue

        for (const [, messages] of results) {
          for (const [id, fields] of messages) {
            await this.processMessage(id, fields, 1)
          }
        }
      } catch (err) {
        if (!this.running) break
        backoff = Math.min((backoff || this.initialBackoffMs) * 2, this.maxBackoffMs)
        const wait = Math.round(backoff / 2 + (backoff / 2) * Math.random())
        log().warn({ err, retryInMs: wait }, 'consumer loop failed, retrying')
        await this.sleep(wait)
      }
    }
  }

  /** Take or extend the consumer lock. */
  private async holdLock(): Promise<boolean> {
    const redis = this.redis!
    if ((await redis.set(LOCK_KEY, this.holder, 'PX', this.lockTtlMs, 'NX')) === 'OK') return true
    return Number(await redis.eval(EXTEND_LOCK, 1, LOCK_KEY, this.holder, String(this.lockTtlMs))) === 1
  }

  /** Deliver again every pending event whose delay since its last attempt has passed. */
  private async retryDue(): Promise<void> {
    const pending = await this.redis!.xpending(
      STREAM_KEY, GROUP, '-', '+', String(PENDING_SCAN)
    ) as [string, string, number, number][]

    for (const [id, , idleMs, deliveries] of pending) {
      if (!this.running) return
      // Idle time restarts at every delivery, so it is the time since the last attempt.
      const delay = retryDelayMs(id, deliveries, this.retryBaseMs, this.retryMaxMs)
      if (idleMs < delay) continue
      // Re-checked per event: a slow batch must not outlive the lock and overlap a new holder.
      if (!(await this.holdLock())) return

      // Atomic: an entry claimed by another holder meanwhile is no longer idle enough and is skipped.
      const claimed = await this.redis!.xclaim(
        STREAM_KEY, GROUP, CONSUMER, String(delay), id
      ) as [string, string[] | null][]

      for (const [claimedId, fields] of claimed) {
        await this.processMessage(claimedId, fields, deliveries + 1)
      }
    }
  }

  private async processMessage(id: string, fields: string[] | null, attempt: number): Promise<void> {
    // Parse event from stream fields.
    let data = ''
    for (let i = 0; fields && i < fields.length; i += 2) {
      if (fields[i] === 'data') data = fields[i + 1]
    }
    if (!data) {
      // Trimmed from the stream (MAXLEN) while pending: there is nothing left to deliver or keep.
      log().warn({ eventId: id }, 'pending event no longer in the outbox, released')
      await this.ack(id)
      return
    }

    let event: EntityEvent
    try {
      event = JSON.parse(data)
    } catch {
      await this.deadLetter(id, data, 'unreadable', 'not valid JSON', attempt)
      return
    }

    const age = Date.now() - new Date(event.timestamp).getTime()
    if (age > this.maxAgeMs) {
      const last = await this.redis!.hget(FAILURES_KEY, id).catch(() => null)
      await this.deadLetter(id, data, 'expired', `undelivered after ${Math.round(age / 1000)} s${last ? `; last failure: ${last}` : ''}`, attempt, event)
      return
    }

    // Fan out to all notifiers. All must succeed for ACK.
    const failures: { notifier: string; reason: string; permanent: boolean }[] = []
    for (const notifier of this.notifiers) {
      try {
        const result = await notifier.notify(event)
        if (!result.acknowledged) failures.push({ notifier: notifier.name, reason: 'not acknowledged', permanent: false })
      } catch (err) {
        failures.push({
          notifier: notifier.name,
          reason: err instanceof Error ? err.message : String(err),
          permanent: (err as { permanent?: boolean }).permanent === true,
        })
      }
    }

    if (failures.length === 0) {
      await this.ack(id)
      if (attempt > 1) await this.redis!.hdel(FAILURES_KEY, id).catch(() => 0)
      return
    }

    for (const f of failures) notificationAttemptFailures.labels(f.notifier).inc()
    const reason = failures.map((f) => `${f.notifier}: ${f.reason}`).join('; ')
    if (failures.some((f) => f.permanent)) {
      await this.deadLetter(id, data, 'rejected', reason, attempt, event)
      return
    }
    if (attempt >= this.maxAttempts) {
      await this.deadLetter(id, data, 'attempts_exhausted', reason, attempt, event)
      return
    }

    await this.redis!.hset(FAILURES_KEY, id, reason).catch(() => 0)
    const retryInMs = retryDelayMs(id, attempt, this.retryBaseMs, this.retryMaxMs)
    const context = { eventId: id, entity_type: event.entity_type, action: event.action, attempt, maxAttempts: this.maxAttempts, retryInMs, reason }
    // Warn on the first failure only; the retries of one event are not a new finding each time.
    if (attempt === 1) log().warn(context, 'notification delivery failed, will retry')
    else log().debug(context, 'notification delivery failed again')
  }

  /** Move the event to the dead-letter stream, with why, and release it from the outbox. */
  private async deadLetter(id: string, data: string, why: DeadReason, reason: string, attempts: number, event?: EntityEvent): Promise<void> {
    await this.redis!.multi()
      .xadd(DEAD_LETTER_KEY, 'MAXLEN', '~', DEAD_LETTER_MAXLEN, '*',
        'data', data, 'why', why, 'reason', reason, 'attempts', String(attempts),
        'outbox_id', id, 'failed_at', new Date().toISOString())
      .xack(STREAM_KEY, GROUP, id)
      .hdel(FAILURES_KEY, id)
      .exec()
    notificationsDeadLettered.labels(why).inc()
    log().warn(
      { eventId: id, why, reason, attempts, ...(event ? { entity_type: event.entity_type, action: event.action } : {}), stream: DEAD_LETTER_KEY },
      'notification dead-lettered',
    )
  }

  private async ack(id: string): Promise<void> {
    try {
      await this.redis!.xack(STREAM_KEY, GROUP, id)
    } catch (err) {
      log().error({ err, eventId: id }, 'could not ACK the event')
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const timer = setTimeout(resolve, ms)
      this.abortController?.signal.addEventListener('abort', () => {
        clearTimeout(timer)
        resolve()
      }, { once: true })
    })
  }
}
