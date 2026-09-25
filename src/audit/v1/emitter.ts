import { env } from '../../config/env.js'
import { traceFields } from '../../telemetry/log-correlation.js'
import { auditV1Events, auditV1Failures } from '../../telemetry/metrics.js'
import { catalogEntry, type AuditEventType } from './catalog.js'
import { HashChain } from './chain.js'
import { uuidv7 } from './ids.js'
import { hmac, ipNet, scrubEmails, uaFamily } from './pseudonym.js'
import { auditEventV1Schema, type AuditEventV1, type AuditEventV1Body } from './schema.js'
import type { AuditOutbox } from './outbox.js'

export type { AuditEventV1 } from './schema.js'
export type { AuditOutbox } from './outbox.js'

/**
 * What a caller says about an event. Identity arrives in the clear (it is what the caller has) and
 * leaves pseudonymised: the email, name, IP and session id given here never reach the line.
 */
export interface AuditV1Input {
  event: AuditEventType
  result?: AuditEventV1Body['result']
  reason?: string | null
  severity?: AuditEventV1Body['severity']
  flags?: string[]
  actor: {
    id?: string | null
    email?: string | null
    ip?: string | null
    ua?: string | null
    sessionId?: string | null
    aal?: string | null
    method?: string | null
  }
  target?: { type: string; id?: string | null; email?: string | null } | null
  org_id?: string | null
  site?: string | null
  changes?: AuditEventV1Body['changes']
  source?: string
  request_id?: string | null
  legacy_type?: string
}

export interface AuditV1Sinks {
  /** Writes the line. Synchronous: the event is on stdout before emit's caller continues. */
  write: (event: AuditEventV1) => void
  outbox: AuditOutbox
  chain?: HashChain
}

const SYSTEM = new Set(['system', 'bootstrap'])

function actorOf(a: AuditV1Input['actor']): AuditEventV1Body['actor'] {
  const email = a.email && a.email !== 'anonymous' && a.email !== 'unknown' ? a.email : null
  const type = email && SYSTEM.has(email) ? 'system'
    : email?.endsWith(`@${env.K8S_SA_EMAIL_DOMAIN}`) ? 'service'
    : a.id || email ? 'user' : 'anonymous'
  const auth = a.aal || a.method ? { aal: a.aal ?? undefined, method: a.method ?? undefined } : undefined
  return {
    type,
    id: a.id ?? null,
    // No id to go by (a guard that only had the address, a caller Kratos did not know): the HMAC
    // still lets two events about the same person be put side by side.
    identifier_hmac: !a.id && email && type !== 'system' ? hmac(email.toLowerCase()) : undefined,
    session_id_hash: hmac(a.sessionId),
    ip_net: ipNet(a.ip),
    ip_hmac: hmac(a.ip),
    ua_family: uaFamily(a.ua),
    auth,
  }
}

function targetOf(t: AuditV1Input['target']): AuditEventV1Body['target'] {
  if (!t) return null
  const byEmail = t.email ?? (t.id?.includes('@') ? t.id : null)
  return {
    type: t.type,
    id: t.id && !t.id.includes('@') ? scrubEmails(t.id) : null,
    identifier_hmac: byEmail ? hmac(byEmail.toLowerCase()) : undefined,
  }
}

function changesOf(c: AuditV1Input['changes']): AuditEventV1Body['changes'] {
  if (!c) return undefined
  const list = (xs?: string[]) => xs?.map(scrubEmails)
  return {
    resource: c.resource,
    id: c.id ? scrubEmails(c.id) : undefined,
    added: list(c.added),
    removed: list(c.removed),
    changedKeys: c.changedKeys,
    summary: c.summary ? scrubEmails(c.summary) : undefined,
  }
}

export function buildEvent(input: AuditV1Input, now = Date.now()): AuditEventV1Body {
  const entry = catalogEntry(input.event) // throws on a key outside the catalog
  return {
    log_type: 'audit',
    schema: 'audit/v1',
    event_id: uuidv7(now),
    ts: new Date(now).toISOString(),
    event: input.event,
    category: entry.category,
    action: entry.action,
    result: input.result ?? 'success',
    reason: input.reason ? scrubEmails(input.reason) : null,
    severity: input.severity ?? entry.severity,
    flags: input.flags ?? [],
    actor: actorOf(input.actor),
    target: targetOf(input.target),
    org_id: input.org_id ?? null,
    site: input.site ?? null,
    changes: changesOf(input.changes),
    source: input.source ?? 'jinbe',
    service_version: env.APP_VERSION || env.COMMIT_SHA || undefined,
    request_id: input.request_id ?? null,
    legacy_type: input.legacy_type,
    ...traceFields(),
  }
}

export class AuditV1Emitter {
  constructor(private sinks: AuditV1Sinks) {}

  /** Swaps where events go — tests, and a future archiver-side writer. */
  useSinks(sinks: Partial<AuditV1Sinks>): void {
    this.sinks = { ...this.sinks, ...sinks }
  }

  /**
   * Validates, chains, writes the line and appends to the outbox. Never throws: a failed audit write
   * is counted (jinbe_audit_v1_failures_total{sink}) and logged, and the business call goes on.
   * Returns the event as written, or null when it was refused by the schema.
   */
  async emit(input: AuditV1Input): Promise<AuditEventV1 | null> {
    let body: AuditEventV1Body
    try {
      body = auditEventV1Schema.parse(buildEvent(input))
    } catch (err) {
      auditV1Failures.labels('schema').inc()
      reportFailure('schema', err, input.event)
      return null
    }
    this.sinks.chain ??= new HashChain()
    const event = this.sinks.chain.seal(body)

    try {
      this.sinks.write(event)
      auditV1Events.labels(event.category, event.result).inc()
    } catch (err) {
      auditV1Failures.labels('log').inc()
      reportFailure('log', err, event.event)
    }
    try {
      await this.sinks.outbox.append(event)
    } catch (err) {
      auditV1Failures.labels('outbox').inc()
      reportFailure('outbox', err, event.event)
    }
    return event
  }
}

// Written to stderr on purpose: the failing sink may be the logger itself. Names the event type
// only — never the event, which is what failed to be stored safely.
function reportFailure(sink: string, err: unknown, event: string): void {
  const message = err instanceof Error ? err.message.split('\n')[0] : String(err)
  process.stderr.write(`${JSON.stringify({ level: 'error', log_type: 'app', msg: 'audit v1 sink failed', sink, event, err: message })}\n`)
}
