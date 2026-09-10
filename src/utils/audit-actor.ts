import type { FastifyRequest } from 'fastify'
import type { AuditActor } from '../services/audit-event.service.js'

/**
 * Shared audit-actor resolver (A4/P2-5). Single source of truth for the actor
 * shape stamped on every audit emit — `email/name/ip/ua/sessionId` from the
 * Kratos-validated session context plus a `requestId` read from the
 * `x-request-id` header (set by request-id middleware; note `request.id` is a
 * separate Fastify id). Replaces the ad-hoc `{email, ip}` builders.
 *
 * Threading the same `requestId` through a mutation's cascade child-events
 * (e.g. deleteGroup fan-out, createService auto-populate) lets the UI correlate
 * everything one action produced.
 */
export function auditActor(request: FastifyRequest): AuditActor & { requestId: string | null } {
  const uc = request.userContext
  const headers = request.headers ?? {}
  const email = uc?.email && uc.email !== 'unknown' ? uc.email : null
  const name = uc?.name && uc.name !== 'unknown' ? uc.name : null
  return {
    // The IMMUTABLE identity, first. An address can be changed by its owner and reused by somebody
    // else, so a trail keyed on one says less every year — and the gates that read this actor decide
    // who may hand out rights, which must not follow an address around.
    id: uc?.id && uc.id !== 'unknown' ? uc.id : null,
    email,
    name,
    ip: request.ip ?? null,
    ua: (headers['user-agent'] as string) || null,
    sessionId: uc?.sessionId ?? request.validatedSession?.sessionId ?? null,
    requestId: (headers['x-request-id'] as string) || null,
  }
}
