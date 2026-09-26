import { auditEventService, type AuditActorInput, type AuditEvent } from '../services/audit-event.service.js'
import { getRedisClient } from '../services/redis-client.service.js'
import type { AuditEventType } from './v1/catalog.js'

/**
 * Emit helpers for the commands that had no audit event (AUD-4), each on its own catalog key.
 *
 * All go through `auditEventService.emit` (so AUDIT_SINK decides legacy / dual / v1) and all are
 * fire-and-forget: a command is never failed because its record could not be stored — the emitter
 * counts that failure where AU-15 looks for it.
 */

function send(event: AuditEvent): void {
  try {
    auditEventService.emit(event).catch(() => {})
  } catch {
    // The emitter never throws; nothing here may turn a done command into an error.
  }
}

function actorOf(actor: AuditActorInput) {
  return { id: actor.id ?? null, email: actor.email ?? null, ip: actor.ip ?? null, ua: actor.ua ?? null, sessionId: actor.sessionId ?? null }
}

// ─── Sites ──────────────────────────────────────────────────────────────────

export type SiteCommand = 'draft' | 'discard' | 'save' | 'apply' | 'rollback' | 'pause' | 'resume' | 'delete'

export const SITE_EVENTS: Record<SiteCommand, AuditEventType> = {
  draft: 'site.draft_saved',
  discard: 'site.draft_discarded',
  save: 'site.saved',
  apply: 'site.applied',
  rollback: 'site.rolled_back',
  pause: 'site.paused',
  resume: 'site.resumed',
  delete: 'site.deleted',
}

/**
 * One event per Site command, for the sites module to call. `summary` is plain language ("applied
 * version 4"); `version` and `rules` are the only structured facts carried — never the intent.
 */
export function auditSite(
  command: SiteCommand,
  name: string,
  actor: AuditActorInput,
  opts: { summary?: string; version?: number; rules?: string[]; result?: 'ok' | 'applied' | 'failed' } = {},
): void {
  const details: Record<string, unknown> = {}
  if (opts.version !== undefined) details.version = opts.version
  if (opts.rules) details.rules = opts.rules
  send({
    category: 'service',
    kind: 'change',
    verb: command,
    target: `site:${name}`,
    targetType: 'site',
    targetId: name,
    service: name,
    result: opts.result ?? (command === 'apply' || command === 'rollback' ? 'applied' : 'ok'),
    actor: actorOf(actor),
    requestId: actor.requestId ?? null,
    changes: { resource: 'site', id: name, summary: opts.summary ?? command },
    ...(Object.keys(details).length ? { details } : {}),
    source: 'jinbe-api',
    v1Event: SITE_EVENTS[command],
  })
}

// ─── Access check ───────────────────────────────────────────────────────────

/**
 * `access.checked`: who asked what somebody ELSE may do. A read, but it discloses another person's
 * rights, so it is recorded. The subject is known here by address only; audit/v1 keeps an HMAC of it.
 */
export function auditAccessCheck(
  actor: AuditActorInput,
  question: { email: string; method: string; path: string; app?: string },
  answer: { allow: boolean; reason: string },
): void {
  send({
    category: 'access',
    kind: 'access',
    verb: 'check',
    target: `user:${question.email}`,
    targetType: 'user',
    result: 'ok',
    actor: actorOf(actor),
    requestId: actor.requestId ?? null,
    ...(question.app ? { service: question.app } : {}),
    details: { targetEmail: question.email, route: `${question.method} ${question.path}`, allow: answer.allow, verdict: answer.reason },
    source: 'jinbe-api',
    v1Event: 'access.checked',
  })
}

// ─── API-key use ────────────────────────────────────────────────────────────

const DAY_S = 86_400

/**
 * `apikey.used`, at most once per client per UTC day: the first resolution of a client id by a
 * cluster-internal caller (the introspection path). Sampled on purpose — a per-request event would
 * bury every change under traffic — and "first use today" is what an investigation asks.
 */
export async function recordApiKeyUse(clientId: string, organizationId: string | null): Promise<void> {
  const day = new Date().toISOString().slice(0, 10)
  try {
    const first = await getRedisClient().set(`auth:audit:apikey_used:${day}:${clientId}`, '1', 'EX', DAY_S, 'NX')
    if (first !== 'OK') return
  } catch {
    // Redis down: record the use rather than lose it — a duplicate is cheaper than a gap.
  }
  send({
    category: 'secret',
    kind: 'access',
    verb: 'use',
    target: `oauth2_client:${clientId}`,
    targetType: 'oauth2_client',
    targetId: clientId,
    result: 'ok',
    actor: { email: null },
    details: { organizationId },
    source: 'jinbe-api',
    v1Event: 'apikey.used',
  })
}
