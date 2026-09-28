import { describe, it, expect, beforeEach, vi } from 'vitest'

// The audit/v1 outbox is drained by the archiver (AUD-7) and then never trimmed. Without one nothing
// drains it, so it is capped instead of growing until Redis runs out of memory.

const xadd = vi.hoisted(() => vi.fn(async () => '1-0'))
const env = vi.hoisted(() => ({ AUDIT_OUTBOX_STREAM: 'auth:audit:outbox', AUDIT_ARCHIVE_ENABLED: false, AUDIT_OUTBOX_MAX_LEN: 100_000 }))
vi.mock('../../../services/redis-client.service.js', () => ({ getRedisClient: () => ({ xadd }) }))
vi.mock('../../../config/env.js', () => ({ env }))

import { redisAuditOutbox } from '../../../audit/v1/outbox.js'
import type { AuditEventV1 } from '../../../audit/v1/schema.js'

const event = { event_id: 'e-1', event_type: 'auth.login.succeeded' } as unknown as AuditEventV1

beforeEach(() => {
  xadd.mockClear()
  env.AUDIT_ARCHIVE_ENABLED = false
  env.AUDIT_OUTBOX_MAX_LEN = 100_000
})

describe('redisAuditOutbox.append', () => {
  it('without an archiver: XADD MAXLEN ~ AUDIT_OUTBOX_MAX_LEN', async () => {
    env.AUDIT_OUTBOX_MAX_LEN = 5_000
    expect(await redisAuditOutbox.append(event)).toBe('1-0')
    expect(xadd).toHaveBeenCalledWith('auth:audit:outbox', 'MAXLEN', '~', 5_000, '*', 'event_id', 'e-1', 'event', JSON.stringify(event))
  })

  it('with an archiver: never trimmed by count', async () => {
    env.AUDIT_ARCHIVE_ENABLED = true
    await redisAuditOutbox.append(event)
    expect(xadd).toHaveBeenCalledWith('auth:audit:outbox', '*', 'event_id', 'e-1', 'event', JSON.stringify(event))
  })
})
