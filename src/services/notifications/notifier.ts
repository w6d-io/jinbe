import type Redis from 'ioredis'
import type { EntityEvent, Notifier } from './types.js'

const STREAM_KEY = 'notifications:outbox'
const GROUP = 'notification-service'
const CONSUMER = 'worker-1'
const BATCH_SIZE = 10
const BLOCK_MS = 5_000
const PENDING_CLAIM_MS = 30_000

interface NotificationServiceConfig {
  /** Max age in ms before an event is dismissed. Default: 1 hour. */
  maxAgeMs?: number
  /** Initial backoff in ms between retry cycles. Default: 1000. */
  initialBackoffMs?: number
  /** Max backoff in ms. Default: 30000. */
  maxBackoffMs?: number
}

const DEFAULT_MAX_AGE_MS = 60 * 60 * 1000
const DEFAULT_INITIAL_BACKOFF_MS = 1_000
const DEFAULT_MAX_BACKOFF_MS = 30_000

/**
 * NotificationService uses a Redis Stream as a durable outbox.
 *
 * - emit() writes events to the stream (fast, non-blocking for the caller).
 * - start() spawns a consumer loop that reads events, fans out to all
 *   registered Notifiers, and ACKs on success.
 * - Failed events stay pending and are reclaimed after PENDING_CLAIM_MS.
 * - Events older than maxAgeMs are dismissed (ACK'd without delivery).
 */
export class NotificationService {
  private redis: Redis | null = null
  private notifiers: Notifier[] = []
  private running = false
  private abortController: AbortController | null = null

  private readonly maxAgeMs: number
  private readonly initialBackoffMs: number
  private readonly maxBackoffMs: number

  constructor(config: NotificationServiceConfig = {}) {
    this.maxAgeMs = config.maxAgeMs ?? DEFAULT_MAX_AGE_MS
    this.initialBackoffMs = config.initialBackoffMs ?? DEFAULT_INITIAL_BACKOFF_MS
    this.maxBackoffMs = config.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS
  }

  /** Set the Redis client (call before start). */
  setRedis(redis: Redis): void {
    this.redis = redis
  }

  /** Register a transport notifier. */
  register(notifier: Notifier): void {
    this.notifiers.push(notifier)
    console.log(`[notifications] Registered notifier: ${notifier.name}`)
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
      console.error('[notifications] Failed to write to stream:', err)
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
      console.error('[notifications] Consumer loop crashed:', err)
      this.running = false
    })
    console.log('[notifications] Consumer started')
  }

  /** Stop the consumer loop. */
  stop(): void {
    this.running = false
    this.abortController?.abort()
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
        // Reclaim old pending messages first.
        await this.reclaimPending()

        // Read new messages.
        const results = await this.redis!.xreadgroup(
          'GROUP', GROUP, CONSUMER,
          'COUNT', String(BATCH_SIZE),
          'BLOCK', String(BLOCK_MS),
          'STREAMS', STREAM_KEY, '>'
        ) as [string, [string, string[]][]][] | null

        if (!results || results.length === 0) continue

        for (const [, messages] of results) {
          for (const [id, fields] of messages) {
            await this.processMessage(id, fields)
          }
        }

        backoff = 0
      } catch (err) {
        if (!this.running) break
        backoff = Math.min((backoff || this.initialBackoffMs) * 2, this.maxBackoffMs)
        console.error(`[notifications] Error, retrying in ${backoff}ms:`, err)
        await this.sleep(backoff)
      }
    }
  }

  private async reclaimPending(): Promise<void> {
    try {
      const pending = await this.redis!.xpending(
        STREAM_KEY, GROUP, '-', '+', String(BATCH_SIZE)
      ) as any[]

      for (const entry of pending) {
        const [id, , idleMs] = entry
        if (idleMs < PENDING_CLAIM_MS) continue

        // Claim and reprocess.
        const claimed = await this.redis!.xclaim(
          STREAM_KEY, GROUP, CONSUMER,
          String(PENDING_CLAIM_MS), id
        ) as [string, string[]][]

        for (const [claimedId, fields] of claimed) {
          await this.processMessage(claimedId, fields)
        }
      }
    } catch {
      // Ignore — pending reclaim is best-effort.
    }
  }

  private async processMessage(id: string, fields: string[]): Promise<void> {
    // Parse event from stream fields.
    let data = ''
    for (let i = 0; i < fields.length; i += 2) {
      if (fields[i] === 'data') data = fields[i + 1]
    }
    if (!data) {
      await this.ack(id)
      return
    }

    let event: EntityEvent
    try {
      event = JSON.parse(data)
    } catch {
      console.error(`[notifications] Invalid JSON in message ${id}, dismissing`)
      await this.ack(id)
      return
    }

    // Dismiss if too old.
    const age = Date.now() - new Date(event.timestamp).getTime()
    if (age > this.maxAgeMs) {
      console.warn(`[notifications] Dismissed stale event ${id} (${Math.round(age / 1000)}s old)`)
      await this.ack(id)
      return
    }

    // Fan out to all notifiers. All must succeed for ACK.
    let allOk = true
    for (const notifier of this.notifiers) {
      try {
        const result = await notifier.notify(event)
        if (!result.acknowledged) allOk = false
      } catch (err) {
        allOk = false
        console.warn(
          `[notifications:${notifier.name}] Failed for ${id}:`,
          err instanceof Error ? err.message : err
        )
      }
    }

    if (allOk) {
      await this.ack(id)
    }
    // If not all ok, message stays pending and will be reclaimed.
  }

  private async ack(id: string): Promise<void> {
    try {
      await this.redis!.xack(STREAM_KEY, GROUP, id)
    } catch (err) {
      console.error(`[notifications] Failed to ACK ${id}:`, err)
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
