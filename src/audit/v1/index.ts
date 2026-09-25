import type { Logger } from 'pino'
import { rootLogger } from '../../telemetry/logger.js'
import { AuditV1Emitter } from './emitter.js'
import { redisAuditOutbox } from './outbox.js'

export { AuditV1Emitter, buildEvent, type AuditV1Input, type AuditEventV1 } from './emitter.js'
export { AUDIT_EVENTS, type AuditEventType } from './catalog.js'
export { verifyChain } from './chain.js'
export { redisAuditOutbox } from './outbox.js'

let audit: Logger | undefined

/**
 * The process's audit/v1 emitter: one JSON line per event through a child of the process logger
 * (synchronous stdout, `log_type:"audit"`), and the Redis outbox.
 */
export const auditLog = new AuditV1Emitter({
  write: (event) => {
    if (!audit) {
      audit = rootLogger().child({ component: 'audit' })
      // The audit line is a record, not verbosity: LOG_LEVEL=warn must not switch it off.
      audit.level = 'info'
    }
    audit.info(event, 'audit')
  },
  outbox: redisAuditOutbox,
})
