import { z } from 'zod'
import { AUDIT_CATEGORIES, AUDIT_EVENT_TYPES } from '../v1/catalog.js'
import type { AuditFilter } from './logql.js'

/**
 * The boundary of /api/audit/*: what a client may ask, validated before any query is built.
 * Unknown parameters are refused (`.strict()`) — a `logql=` or `query=` is a 400, not ignored.
 */

export const DAY_MS = 86_400_000
export const MAX_SPAN_MS = 30 * DAY_MS // Loki max_query_length is 30d1h
export const MAX_LOOKBACK_MS = 400 * DAY_MS
export const MAX_EXPORT_SPAN_MS = MAX_LOOKBACK_MS

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/
const EVENT = /^[a-z][a-z_]*(\.[a-z_]+)*(\.\*)?$/

const eventKey = z.string().regex(EVENT).refine(
  (e) => (e.endsWith('.*') ? AUDIT_EVENT_TYPES.some((k) => k.startsWith(e.slice(0, -1))) : (AUDIT_EVENT_TYPES as readonly string[]).includes(e)),
  'not an audit/v1 catalog key or prefix',
)
const many = <T extends z.ZodTypeAny>(item: T) =>
  z.union([item, z.array(item).max(10)]).transform((v) => [v].flat() as z.infer<T>[])

/** The facets a filter may carry — the same set in a query string, an export and a saved query. */
export const filterFields = {
  org: z.string().regex(ID).optional(),
  actor: z.string().regex(ID).optional(),
  target: z.string().regex(/^[A-Za-z0-9._:/ -]{1,256}$/).optional(),
  site: z.string().regex(/^[a-z0-9_-]{1,63}$/).optional(),
  event: many(eventKey).optional(),
  category: z.enum(AUDIT_CATEGORIES).optional(),
  result: z.enum(['success', 'denied', 'failure', 'error']).optional(),
  severity: z.enum(['info', 'warn', 'high']).optional(),
  trace_id: z.string().regex(/^[0-9a-f]{32}$/).optional(),
  q: z.string().min(1).max(64).refine((s) => !LONE_SURROGATE.test(s), 'malformed text').optional(),
}
export const filtersSchema = z.object(filterFields).strict()
export type Filters = z.infer<typeof filtersSchema>

const time = z.string().datetime({ offset: true })
const page = {
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().max(1024).optional(),
}

export const eventsQuerySchema = z.object({ from: time, to: time, ...filterFields, ...page }).strict()
export const facetsQuerySchema = z.object({ from: time, to: time, ...filterFields }).strict()
export const summaryQuerySchema = z.object({
  window: z.string().regex(/^\d{1,4}(m|h|d)$/).default('24h'),
  org: filterFields.org,
}).strict()
export const timelineQuerySchema = z.object({ from: time, to: time, ...page }).strict()
export const myLoginsQuerySchema = z.object({ from: time.optional(), to: time.optional(), ...page }).strict()
export const eventByIdQuerySchema = z.object({ ts: time.optional() }).strict()
export const userIdSchema = z.string().regex(/^[A-Za-z0-9-]{1,64}$/)
export const eventIdSchema = z.string().uuid()

export const exportBodySchema = z.object({
  from: time,
  to: time,
  filters: filtersSchema.default({}),
  format: z.enum(['csv', 'ndjson']).default('ndjson'),
}).strict()

export const savedQueryBodySchema = z.object({
  name: z.string().trim().min(1).max(80),
  filters: filtersSchema,
  shared: z.boolean().default(false),
  orgId: z.string().regex(ID).optional(),
}).strict()

/** The window a request may read: bounded span, bounded lookback, from before to. */
export function checkRange(fromIso: string, toIso: string, maxSpanMs = MAX_SPAN_MS, now = Date.now()):
  { ok: true; fromMs: number; toMs: number } | { ok: false; error: 'range_too_large' | 'invalid_range'; message: string } {
  const fromMs = Date.parse(fromIso)
  const toMs = Math.min(Date.parse(toIso), now)
  if (!(fromMs < toMs)) return { ok: false, error: 'invalid_range', message: '`from` must be before `to` (and before now).' }
  if (toMs - fromMs > maxSpanMs) {
    return { ok: false, error: 'range_too_large', message: `Pick ${Math.round(maxSpanMs / DAY_MS)} days or fewer per view. Use Export for longer periods.` }
  }
  if (now - fromMs > MAX_LOOKBACK_MS) return { ok: false, error: 'range_too_large', message: 'Audit events are kept 400 days.' }
  return { ok: true, fromMs, toMs }
}

/** `24h` → ms. */
export function windowMs(window: string): number {
  const n = Number(window.slice(0, -1))
  return n * ({ m: 60_000, h: 3_600_000, d: DAY_MS } as const)[window.slice(-1) as 'm' | 'h' | 'd']
}

export function toFilter(f: Filters, orgs: string[] | undefined): AuditFilter {
  return {
    orgs, actor: f.actor, target: f.target, site: f.site, events: f.event, category: f.category,
    result: f.result, severity: f.severity, traceId: f.trace_id, q: f.q,
  }
}

// ─── Cursor ─────────────────────────────────────────────────────────────────

/** Where the previous page stopped: the Loki timestamp of its last entry and the events seen at it. */
export interface Cursor { t: string; ids: string[] }

const cursorSchema = z.object({ t: z.string().regex(/^\d{1,20}$/), ids: z.array(z.string().uuid()).max(200) }).strict()

export function encodeCursor(c: Cursor): string {
  return Buffer.from(JSON.stringify(c)).toString('base64url')
}

export function decodeCursor(raw: string): Cursor | null {
  try {
    const parsed = cursorSchema.safeParse(JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')))
    return parsed.success ? parsed.data : null
  } catch {
    return null
  }
}

export function zodMessage(err: z.ZodError): string {
  return err.issues.map((i) => `${i.path.join('.') || 'query'}: ${i.message}`).join('; ')
}
