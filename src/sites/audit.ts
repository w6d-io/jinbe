import { auditEventService, type AuditActorInput } from '../services/audit-event.service.js'

export type Actor = AuditActorInput

/** One audit event per Site command, through the existing emitter only. Best-effort, like its other callers. */
export function auditSite(verb: string, name: string, actor: Actor, summary: string, details?: Record<string, unknown>, result: 'ok' | 'applied' = 'ok'): void {
  Promise.resolve()
    .then(() => auditEventService.emit({
      category: 'service',
      kind: 'change',
      verb,
      target: `site:${name}`,
      targetType: 'site',
      targetId: name,
      service: name,
      result,
      actor: { id: actor.id ?? null, email: actor.email ?? null, ip: actor.ip ?? null, ua: actor.ua ?? null, sessionId: actor.sessionId ?? null },
      requestId: actor.requestId ?? null,
      changes: { resource: 'site', id: name, summary },
      ...(details ? { details } : {}),
      source: 'jinbe-api',
    }))
    .catch(() => {})
}
