import type { AuditEventType } from '../audit/v1/catalog.js'
import { auditEventService, type AuditActorInput } from '../services/audit-event.service.js'
import type { Change } from './validate.js'

export type Actor = AuditActorInput

/**
 * One audit/v1 event per gateway write, through the existing emitter. The changes carry handler
 * names and config key names only — never a value, since values include secret references.
 */
export function auditGateway(
  event: Extract<AuditEventType, 'gateway.changed' | 'gateway.rolled_back'>,
  actor: Actor,
  summary: string,
  details: { changes: Change[]; generation?: number; note?: string },
): void {
  Promise.resolve()
    .then(() => auditEventService.emit({
      category: 'policy',
      kind: 'change',
      verb: event === 'gateway.changed' ? 'update' : 'rollback',
      v1Event: event,
      target: 'gateway:gateway',
      targetType: 'gateway',
      targetId: 'gateway',
      result: 'applied',
      severity: 'high',
      actor: { id: actor.id ?? null, email: actor.email ?? null, ip: actor.ip ?? null, ua: actor.ua ?? null, sessionId: actor.sessionId ?? null },
      requestId: actor.requestId ?? null,
      changes: { resource: 'gateway', id: 'gateway', summary, changedKeys: details.changes.map((c) => `${c.kind}.${c.handler}`) },
      details: { ...details },
      source: 'jinbe-api',
    }))
    .catch(() => {})
}

/**
 * The AU-2 rows for this module (audit/route-events.ts WRITE_ROUTE_AUDIT), spread there by the
 * integration owner: `...GATEWAY_ROUTE_AUDIT`.
 */
export const GATEWAY_ROUTE_AUDIT = {
  'PUT /api/admin/gateway': { event: 'gateway.changed', emit: 'handler' },
  'POST /api/admin/gateway/rollback': { event: 'gateway.rolled_back', emit: 'handler' },
  'POST /api/admin/gateway/preview': { exempt: 'validates a proposed gateway configuration; writes nothing' },
} as const satisfies Record<string, { event: AuditEventType; emit: 'handler' } | { exempt: string }>
