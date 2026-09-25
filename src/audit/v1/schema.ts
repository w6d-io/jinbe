import { z } from 'zod'
import { AUDIT_CATEGORIES, AUDIT_EVENT_TYPES } from './catalog.js'

/**
 * The audit/v1 line, validated before it is written. Identity is by id or HMAC only: the schema
 * refuses any line that still contains an `@` — the cheapest proof that no email got through
 * (CONTROL AU-5 greps the stream for the same character).
 */

const hmac = z.string().regex(/^hmac-sha256:[0-9a-f]{32}$/)

export const auditActorV1Schema = z.object({
  type: z.enum(['user', 'service', 'system', 'anonymous']),
  id: z.string().nullable(),
  identifier_hmac: hmac.optional(),
  session_id_hash: hmac.optional(),
  ip_net: z.string().optional(),
  ip_hmac: hmac.optional(),
  ua_family: z.string().max(32).optional(),
  auth: z.object({ aal: z.string().optional(), method: z.string().optional() }).optional(),
})

export const auditTargetV1Schema = z.object({
  type: z.string().min(1),
  id: z.string().nullable(),
  identifier_hmac: hmac.optional(),
})

export const auditChangesV1Schema = z.object({
  resource: z.string(),
  id: z.string().optional(),
  added: z.array(z.string()).optional(),
  removed: z.array(z.string()).optional(),
  changedKeys: z.array(z.string()).optional(),
  summary: z.string().optional(),
})

export const auditEventV1Schema = z
  .object({
    log_type: z.literal('audit'),
    schema: z.literal('audit/v1'),
    event_id: z.string().uuid(),
    ts: z.string().datetime(),
    event: z.enum(AUDIT_EVENT_TYPES),
    category: z.enum(AUDIT_CATEGORIES),
    action: z.string(),
    result: z.enum(['success', 'denied', 'failure', 'error']),
    reason: z.string().nullable(),
    severity: z.enum(['info', 'warn', 'high']),
    flags: z.array(z.string()),
    actor: auditActorV1Schema,
    target: auditTargetV1Schema.nullable(),
    org_id: z.string().nullable(),
    site: z.string().nullable(),
    changes: auditChangesV1Schema.optional(),
    source: z.string(),
    service_version: z.string().optional(),
    request_id: z.string().nullable(),
    trace_id: z.string().optional(),
    span_id: z.string().optional(),
    legacy_type: z.string().optional(),
  })
  .refine((e) => !JSON.stringify(e).includes('@'), { message: 'an audit/v1 line must not contain an email' })

export type AuditEventV1Body = z.infer<typeof auditEventV1Schema>

/** A body plus its place in the process's hash chain (audit/v1/chain.ts). */
export type AuditEventV1 = AuditEventV1Body & { chain_id: string; seq: number; prev_hash: string; hash: string }
