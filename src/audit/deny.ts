import type { FastifyRequest } from 'fastify'
import { auditEventService, type AuditSeverity } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'

/**
 * The one way a guard records a refusal (AUD-3): `access.denied`, keyed on the SUBJECT id.
 *
 * There were ten copies of the same object literal across the guards. Most carried only the address,
 * some not even that, none the request id — so the trail of refusals could not be joined to the
 * person refused once their address changed, nor to the request that was refused. One helper cannot
 * drift from itself.
 *
 * Fire-and-forget like every emit from a guard: a refusal is answered whether or not it was stored,
 * and a storage failure is counted by the emitter.
 */
export function denyAudit(
  request: FastifyRequest,
  reason: string,
  opts: { source?: string; statusCode?: number; severity?: AuditSeverity } = {},
): void {
  const path = (request.url || '').split('?')[0]
  const actor = auditActor(request)
  try {
    auditEventService.emit({
      category: 'access',
      kind: 'access',
      verb: 'deny',
      target: `${request.method} ${path}`,
      result: 'denied',
      actor: { id: actor.id, email: actor.email, ip: actor.ip, ua: actor.ua, sessionId: actor.sessionId },
      requestId: actor.requestId,
      method: request.method,
      path,
      reason,
      ...(opts.statusCode ? { statusCode: opts.statusCode } : {}),
      ...(opts.severity ? { severity: opts.severity } : {}),
      source: opts.source ?? 'jinbe-api',
      v1Event: 'access.denied',
    }).catch(() => {})
  } catch {
    // The emitter never throws; a mocked or half-initialised one must not turn a 403 into a 500.
  }
}
