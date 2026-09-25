import { getRedisClient } from '../../services/redis-client.service.js'
import { env } from '../../config/env.js'
import type { AuditEventV1 } from './schema.js'

/**
 * Durable copy of every audit/v1 event (AUD-1b).
 *
 * The log line is best effort once it leaves the process: a pod killed before the collector reads
 * its file, a lagging or missing collector. The outbox holds each event until the archive (AUD-7)
 * confirms it stored it, then `ack` removes it. It is NEVER trimmed by count — a cap would drop
 * exactly the events an outage failed to deliver. It stays until AU-15 shows zero loss for 30 days.
 */
export interface AuditOutbox {
  append(event: AuditEventV1): Promise<string>
}

export const redisAuditOutbox = {
  async append(event: AuditEventV1): Promise<string> {
    const id = await getRedisClient().xadd(env.AUDIT_OUTBOX_STREAM, '*', 'event_id', event.event_id, 'event', JSON.stringify(event))
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
