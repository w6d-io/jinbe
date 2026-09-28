import { getRedisClient } from '../../services/redis-client.service.js'
import { env } from '../../config/env.js'
import type { AuditEventV1 } from './schema.js'

/**
 * Durable copy of every audit/v1 event (AUD-1b).
 *
 * The log line is best effort once it leaves the process: a pod killed before the collector reads
 * its file, a lagging or missing collector. The outbox holds each event until the archive (AUD-7)
 * confirms it stored it, then `ack` removes it. With an archiver (AUDIT_ARCHIVE_ENABLED) it is NEVER
 * trimmed by count — a cap would drop exactly the events an outage failed to deliver. It stays until
 * AU-15 shows zero loss for 30 days.
 *
 * Without one nothing ever drains it, so the stream is capped (XADD MAXLEN ~ AUDIT_OUTBOX_MAX_LEN):
 * it keeps the latest events for a replay instead of growing until Redis runs out of memory.
 */
export interface AuditOutbox {
  append(event: AuditEventV1): Promise<string>
}

/**
 * TODO(AUD-7): the archiver this outbox is built for. One leader loop per deployment:
 *   1. `pending(n)` — oldest first;
 *   2. write them to the Object-Lock (WORM, compliance mode) bucket as one immutable object, keyed so a
 *      retry overwrites nothing (e.g. by the first and last stream id);
 *   3. `ack(ids)` only once the bucket confirmed the write — never before, never on a partial write.
 * Turning it on means setting AUDIT_ARCHIVE_ENABLED=true, which also stops the cap below and makes the
 * Home alarm on archive lag again.
 */
export interface AuditArchiver {
  /** Drain one batch. Resolves with how many events were stored and acknowledged. */
  drainOnce(): Promise<number>
}

export const redisAuditOutbox = {
  async append(event: AuditEventV1): Promise<string> {
    const fields = ['event_id', event.event_id, 'event', JSON.stringify(event)]
    const id = env.AUDIT_ARCHIVE_ENABLED
      ? await getRedisClient().xadd(env.AUDIT_OUTBOX_STREAM, '*', ...fields)
      : await getRedisClient().xadd(env.AUDIT_OUTBOX_STREAM, 'MAXLEN', '~', env.AUDIT_OUTBOX_MAX_LEN, '*', ...fields)
    return id ?? ''
  },

  /** Oldest events first, for the archiver. */
  async pending(count = 500): Promise<Array<{ id: string; event: AuditEventV1 }>> {
    const rows = await getRedisClient().xrange(env.AUDIT_OUTBOX_STREAM, '-', '+', 'COUNT', count)
    return rows.map(([id, fields]) => ({ id, event: JSON.parse(fields[fields.indexOf('event') + 1]) as AuditEventV1 }))
  },

  /** Called by the archiver once the events are stored in the Object-Lock bucket — and not before. */
  async ack(ids: string[]): Promise<number> {
    return ids.length ? getRedisClient().xdel(env.AUDIT_OUTBOX_STREAM, ...ids) : 0
  },
}
