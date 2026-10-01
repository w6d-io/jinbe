import { auditEventService, type AuditActor, type AuditResult } from '../services/audit-event.service.js'
import { catalogEntry, type AuditEventType } from '../audit/v1/catalog.js'

/**
 * One audit/v1 event of browser sign-in (catalog `mcp.oauth.*`). Fire-and-forget: a failed write is
 * counted by the emitter and never fails the sign-in.
 */
export function oauthAudit(
  event: Extract<AuditEventType, `mcp.${string}`>,
  e: { actor: AuditActor & { requestId?: string | null }; targetId: string; targetType?: 'oauth2_client' | 'user'; result?: AuditResult; reason?: string; details?: Record<string, unknown> },
): void {
  const { severity } = catalogEntry(event)
  const { requestId, ...actor } = e.actor
  auditEventService.emit({
    category: event === 'mcp.oauth.login_refused' || event === 'mcp.oauth.consent_denied' ? 'auth' : 'secret',
    verb: event.split('.').at(-1) as string,
    target: `${e.targetType ?? 'oauth2_client'}:${e.targetId}`,
    targetType: e.targetType ?? 'oauth2_client',
    targetId: e.targetId,
    result: e.result ?? 'applied',
    severity,
    actor,
    requestId: requestId ?? null,
    ...(e.reason ? { reason: e.reason } : {}),
    ...(e.details ? { details: e.details } : {}),
    source: 'jinbe-api',
    v1Event: event,
  }).catch(() => {})
}
