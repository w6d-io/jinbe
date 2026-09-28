import { env } from '../../config/env.js'
import { quote } from '../query/logql.js'
import { lokiClient, LokiUnavailableError, type LokiSample } from '../query/loki.js'
import { countsOver, histogramStep } from '../query/reader.js'

/**
 * Gateway decisions, read from the gateway's own log (Oathkeeper writes one line per request:
 * `Access request granted` / `Access request denied`, with `granted`, `subject`, `http_host`).
 *
 * The audit trail only ever held refusals — jinbe's own guards write `access.denied`, and nothing
 * wrote what the gateway let through. One event per request would bury every change under traffic,
 * so decisions are read as COUNTS: per subject and host over a window (this file, for the console),
 * and per subject and host per hour into the trail itself (rollup.ts).
 *
 * Only the subject id and the host are grouped on: a path is open-ended (ids, scanner probes — more
 * than Loki's 500 series in a day on the sandbox), and the line carries no organisation.
 */

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** No subject, or Oathkeeper's `anonymous` authenticator's placeholder: nobody signed in. */
export const isUnauthenticated = (subject: string) => subject === '' || subject === 'guest'

/** A Kratos identity is a UUID; anything else the gateway names is an OAuth2 client — a machine. */
export const subjectKind = (subject: string): 'user' | 'service' | 'anonymous' =>
  isUnauthenticated(subject) ? 'anonymous' : UUID.test(subject) ? 'user' : 'service'

export interface GatewayFilter {
  subject?: string
  host?: string
}

export function gatewayQuery(f: GatewayFilter = {}, namespace = env.LOKI_NAMESPACE, container = env.LOKI_GATEWAY_CONTAINER): string {
  const labels = [...(namespace ? [`namespace=${quote(namespace)}`] : []), `container=${quote(container)}`]
  const stages = ['|= "Access request"', '| json granted="granted", subject="subject", host="http_host"']
  if (f.subject) stages.push(`| subject=${quote(f.subject)}`)
  if (f.host) stages.push(`| host=${quote(f.host)}`)
  return `{${labels.join(', ')}} ${stages.join(' ')}`
}

export interface Tally { allowed: number; denied: number }
export interface SubjectRow extends Tally { subject: string; kind: 'user' | 'service'; hosts: string[] }
export interface HostRow extends Tally { host: string; unauthenticated: number }
export interface GatewayBucket extends Tally { t: string }

export interface GatewayAccess {
  totals: Tally & { unauthenticated: Tally }
  subjects: SubjectRow[]
  hosts: HostRow[]
  series: GatewayBucket[]
  /** More subjects than listed, or the breakdown fell back to a top-k. */
  truncated: boolean
}

const TOP_SUBJECTS = 50
const TOP_HOSTS = 30

const tallyOf = (granted: string, n: number): Tally => (granted === 'true' ? { allowed: n, denied: 0 } : { allowed: 0, denied: n })

/** Folds `sum by (granted, subject, host)` samples into the per-subject and per-host tables. */
export function fold(samples: LokiSample[]): Omit<GatewayAccess, 'series' | 'truncated'> & { subjectCount: number } {
  const totals = { allowed: 0, denied: 0, unauthenticated: { allowed: 0, denied: 0 } }
  const subjects = new Map<string, SubjectRow & { perHost: Map<string, number> }>()
  const hosts = new Map<string, HostRow>()
  for (const { metric, value } of samples) {
    const subject = metric.subject ?? ''
    const host = metric.host ?? ''
    const t = tallyOf(metric.granted ?? '', value)
    totals.allowed += t.allowed
    totals.denied += t.denied
    const h = hosts.get(host) ?? { host, allowed: 0, denied: 0, unauthenticated: 0 }
    h.allowed += t.allowed
    h.denied += t.denied
    hosts.set(host, h)
    if (isUnauthenticated(subject)) {
      totals.unauthenticated.allowed += t.allowed
      totals.unauthenticated.denied += t.denied
      h.unauthenticated += value
      continue
    }
    const kind = subjectKind(subject) as 'user' | 'service'
    const row = subjects.get(subject) ?? { subject, kind, allowed: 0, denied: 0, hosts: [], perHost: new Map() }
    row.allowed += t.allowed
    row.denied += t.denied
    row.perHost.set(host, (row.perHost.get(host) ?? 0) + value)
    subjects.set(subject, row)
  }
  const byTotal = <T extends Tally>(a: T, b: T) => b.allowed + b.denied - (a.allowed + a.denied)
  return {
    totals,
    subjectCount: subjects.size,
    subjects: [...subjects.values()].sort(byTotal).slice(0, TOP_SUBJECTS).map(({ perHost, ...row }) => ({
      ...row,
      hosts: [...perHost.entries()].sort(([, a], [, b]) => b - a).map(([host]) => host).filter(Boolean).slice(0, 5),
    })),
    hosts: [...hosts.values()].filter((h) => h.host !== '').sort(byTotal).slice(0, TOP_HOSTS),
  }
}

const tooWide = (err: unknown) => err instanceof LokiUnavailableError && err.status === 400

/**
 * Allowed and denied over [from, to], by subject and host, with a histogram. Two counts, both
 * cacheable by Loki (countsOver): the histogram by `granted` alone, the breakdown by
 * (granted, subject, host). A breakdown over Loki's series limit falls back to its top 200.
 */
export async function gatewayAccess(f: GatewayFilter, fromMs: number, toMs: number): Promise<GatewayAccess> {
  const query = gatewayQuery(f)
  const display = histogramStep((toMs - fromMs) / 1000)
  const [byGranted, breakdown] = await Promise.all([
    countsOver(query, 'granted', fromMs, toMs, display),
    countsOver(query, 'granted, subject, host', fromMs, toMs, display)
      .then((w) => ({ samples: w.total, fellBack: false }))
      .catch(async (err) => {
        if (!tooWide(err)) throw err
        const rangeS = Math.max(1, Math.round((toMs - fromMs) / 1000))
        const samples = await lokiClient().instant(`topk(200, sum by (granted, subject, host) (count_over_time(${query} [${rangeS}s])))`, toMs / 1000)
        return { samples, fellBack: true }
      }),
  ])
  const folded = fold(breakdown.samples)
  const first = Math.floor(fromMs / 1000 / display) * display
  const last = Math.ceil(toMs / 1000 / display) * display
  const buckets = new Map<number, GatewayBucket>()
  for (let t = first; t < last; t += display) buckets.set(t, { t: new Date(t * 1000).toISOString(), allowed: 0, denied: 0 })
  for (const [end, samples] of byGranted.points) {
    const b = buckets.get(Math.floor((end - 1) / display) * display)
    if (!b) continue
    for (const s of samples) {
      const t = tallyOf(s.metric.granted ?? '', s.value)
      b.allowed += t.allowed
      b.denied += t.denied
    }
  }
  return {
    // The histogram's count is complete even when the breakdown is only a top-k.
    totals: breakdown.fellBack ? { ...folded.totals, ...sumTallies(byGranted.total) } : folded.totals,
    subjects: folded.subjects,
    hosts: folded.hosts,
    series: [...buckets.values()],
    truncated: breakdown.fellBack || folded.subjectCount > folded.subjects.length,
  }
}

function sumTallies(samples: LokiSample[]): Tally {
  return samples.reduce((acc, s) => {
    const t = tallyOf(s.metric.granted ?? '', s.value)
    return { allowed: acc.allowed + t.allowed, denied: acc.denied + t.denied }
  }, { allowed: 0, denied: 0 })
}
