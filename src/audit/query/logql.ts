/**
 * The only place LogQL is written (AUD-9, OBS-4.1). The client never sends a query: it sends
 * allow-listed fields, validated at the route, and every value lands here inside ONE double-quoted
 * literal. Loki unquotes those literals the way Go's strconv.Unquote does, so escaping `\`, `"` and
 * control characters is enough for a value to be searched for and never parsed as syntax (AU-12).
 */
import { env } from '../../config/env.js'

/** A Go/LogQL double-quoted string literal whose content reads back exactly as `value`. */
export function quote(value: string): string {
  let out = '"'
  for (const ch of value) {
    const code = ch.charCodeAt(0)
    if (ch === '\\') out += '\\\\'
    else if (ch === '"') out += '\\"'
    else if (ch === '\n') out += '\\n'
    else if (ch === '\r') out += '\\r'
    else if (ch === '\t') out += '\\t'
    else if (code < 0x20 || code === 0x7f) out += `\\u${code.toString(16).padStart(4, '0')}`
    else out += ch
  }
  return `${out}"`
}

/** RE2 metacharacters escaped, so a value inside a regex matches only itself. */
export function escapeRegex(value: string): string {
  return value.replace(/[\\^$.|?*+()[\]{}]/g, '\\$&')
}

/** `"a|b"` — an exact match on any of the values (Loki anchors label regexes). */
export function regexAlternation(values: string[]): string {
  return quote(values.map(escapeRegex).join('|'))
}

/** `org.grants.*` is a prefix; anything else is an exact key. The route allow-lists both forms. */
const PREFIX = /^[a-z][a-z_]*(\.[a-z_]+)*\.\*$/

export interface AuditFilter {
  /** undefined = every org (platform reader). An array = exactly these; empty is refused. */
  orgs?: string[]
  actor?: string
  /** Only these kinds of actor (user / service / system / anonymous) — how unauthenticated noise is hidden. */
  actorTypes?: string[]
  target?: string
  /** The user as actor OR target (timeline, own logins). */
  subject?: string
  site?: string
  events?: string[]
  category?: string
  result?: string
  severity?: string
  traceId?: string
  q?: string
  eventId?: string
  /** One process's hash chain, seq in [from, to] — the neighbours an event is verified against. */
  chain?: { id: string; from: number; to: number }
}

/**
 * How the audit stream is found (LOKI_AUDIT_SELECTOR). `label`: a `log_type` stream label, which
 * the collector has to promote. `json`: no such label — jinbe's container, narrowed on the raw line,
 * then on the parsed `log_type` field, which is what decides.
 */
export interface AuditStream {
  mode: 'label' | 'json'
  container: string
}

export const auditStream = (): AuditStream => ({ mode: env.LOKI_AUDIT_SELECTOR, container: env.LOKI_AUDIT_CONTAINER })

// pino writes compact JSON, so the audit line carries this exact text; the `| json` stage confirms it.
const AUDIT_LINE = quote('"log_type":"audit"')

export function auditSelector(namespace?: string, stream = auditStream()): string {
  if (stream.mode === 'json') {
    const labels = namespace ? [`namespace=${quote(namespace)}`] : []
    return `{${[...labels, `container=${quote(stream.container)}`].join(', ')}} |= ${AUDIT_LINE}`
  }
  return namespace ? `{log_type="audit", namespace=${quote(namespace)}}` : '{log_type="audit"}'
}

function eventFilter(events: string[]): string {
  if (events.length === 1 && !PREFIX.test(events[0])) return `event=${quote(events[0])}`
  const parts = events.map((e) => (PREFIX.test(e) ? `${escapeRegex(e.slice(0, -2))}\\..*` : escapeRegex(e)))
  return `event=~${quote(parts.join('|'))}`
}

/** The label-filter stages after `| json`, in a fixed order — the shape never depends on values. */
export function auditPipeline(f: AuditFilter, stream = auditStream()): string {
  if (f.orgs && f.orgs.length === 0) throw new Error('an empty org scope would read nothing — refuse it upstream')
  const stages: string[] = []
  // Free text first, as a line filter on the raw line: cheapest, and it cannot reach the labels.
  if (f.q) stages.push(`|= ${quote(f.q)}`)
  stages.push('| json')
  if (stream.mode === 'json') stages.push('| log_type="audit"')
  if (f.orgs) stages.push(f.orgs.length === 1 ? `| org_id=${quote(f.orgs[0])}` : `| org_id=~${regexAlternation(f.orgs)}`)
  if (f.subject) stages.push(`| actor_id=${quote(f.subject)} or target_id=${quote(f.subject)}`)
  if (f.actor) stages.push(`| actor_id=${quote(f.actor)}`)
  if (f.actorTypes?.length) stages.push(f.actorTypes.length === 1 ? `| actor_type=${quote(f.actorTypes[0])}` : `| actor_type=~${regexAlternation(f.actorTypes)}`)
  if (f.target) stages.push(`| target_id=${quote(f.target)}`)
  if (f.site) stages.push(`| site=${quote(f.site)}`)
  if (f.events?.length) stages.push(`| ${eventFilter(f.events)}`)
  if (f.category) stages.push(`| category=${quote(f.category)}`)
  if (f.result) stages.push(`| result=${quote(f.result)}`)
  if (f.severity) stages.push(`| severity=${quote(f.severity)}`)
  if (f.traceId) stages.push(`| trace_id=${quote(f.traceId)}`)
  if (f.eventId) stages.push(`| event_id=${quote(f.eventId)}`)
  if (f.chain) {
    if (!Number.isSafeInteger(f.chain.from) || !Number.isSafeInteger(f.chain.to)) throw new Error('chain bounds must be integers')
    stages.push(`| chain_id=${quote(f.chain.id)} | seq >= ${f.chain.from} | seq <= ${f.chain.to}`)
  }
  return stages.join(' ')
}

export function auditQuery(f: AuditFilter, namespace?: string, stream = auditStream()): string {
  return `${auditSelector(namespace, stream)} ${auditPipeline(f, stream)}`
}

/** `sum by (<field>) (count_over_time(<query> [<seconds>s]))`, optionally top-k. */
export function countBy(query: string, field: string | null, rangeS: number, topk?: number): string {
  const inner = `count_over_time(${query} [${Math.max(1, Math.round(rangeS))}s])`
  const sum = field ? `sum by (${field}) (${inner})` : `sum(${inner})`
  return topk ? `topk(${topk}, ${sum})` : sum
}
