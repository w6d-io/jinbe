import { env } from '../../config/env.js'

/**
 * The Loki HTTP API, as jinbe uses it: log range queries and metric (instant / range) queries.
 *
 * In-cluster, no auth and no tenant header (`auth_enabled: false`) — which is exactly why every
 * query is built and scoped by jinbe and never taken from a client. Anything but a 2xx, a timeout or
 * a refused connection is `LokiUnavailableError`, which the routes answer as 503: an unreachable
 * store must never read as an empty trail (CONTROL AU-11).
 */

export const MAX_ENTRIES = 5000 // Loki max_entries_limit_per_query

export interface LokiEntry {
  /** Nanoseconds since the epoch, as Loki returns it (a string: it does not fit a double). */
  ts: string
  line: string
  labels: Record<string, string>
}

export interface LokiRangeParams {
  query: string
  startNs: string
  endNs: string
  limit: number
  direction: 'backward' | 'forward'
}

export interface LokiSample { metric: Record<string, string>; value: number }
export interface LokiSeries { metric: Record<string, string>; values: Array<[number, number]> }

export interface LokiClient {
  queryRange(params: LokiRangeParams): Promise<LokiEntry[]>
  /** Metric query evaluated at one instant (seconds since the epoch). */
  instant(query: string, atS: number): Promise<LokiSample[]>
  /** Metric query over [start, end] every `stepS` seconds. */
  range(query: string, startS: number, endS: number, stepS: number): Promise<LokiSeries[]>
}

export class LokiUnavailableError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message)
    this.name = 'LokiUnavailableError'
  }
}

type LokiResponse = {
  status?: string
  data?: {
    resultType?: string
    result?: Array<{ stream?: Record<string, string>; metric?: Record<string, string>; values?: Array<[string | number, string]>; value?: [number, string] }>
  }
}

export class HttpLokiClient implements LokiClient {
  constructor(private readonly baseUrl: string, private readonly timeoutMs: number) {}

  private async get(path: string, params: Record<string, string>): Promise<LokiResponse> {
    const url = `${this.baseUrl.replace(/\/$/, '')}${path}?${new URLSearchParams(params)}`
    let res: Response
    try {
      res = await fetch(url, { signal: AbortSignal.timeout(this.timeoutMs) })
    } catch (err) {
      throw new LokiUnavailableError(err instanceof Error ? err.message : String(err))
    }
    if (!res.ok) {
      // The body may echo the query; only the status leaves this function.
      throw new LokiUnavailableError(`loki answered ${res.status}`, res.status)
    }
    return (await res.json()) as LokiResponse
  }

  async queryRange(p: LokiRangeParams): Promise<LokiEntry[]> {
    const body = await this.get('/loki/api/v1/query_range', {
      query: p.query, start: p.startNs, end: p.endNs, limit: String(Math.min(p.limit, MAX_ENTRIES)), direction: p.direction,
    })
    const entries: LokiEntry[] = []
    for (const stream of body.data?.result ?? []) {
      for (const [ts, line] of stream.values ?? []) entries.push({ ts: String(ts), line, labels: stream.stream ?? {} })
    }
    // Loki orders within a stream; across streams the caller needs one order.
    entries.sort((a, b) => (BigInt(a.ts) === BigInt(b.ts) ? 0 : (BigInt(a.ts) < BigInt(b.ts)) === (p.direction === 'backward') ? 1 : -1))
    return entries
  }

  async instant(query: string, atS: number): Promise<LokiSample[]> {
    const body = await this.get('/loki/api/v1/query', { query, time: String(Math.floor(atS)) })
    return (body.data?.result ?? []).map((r) => ({ metric: r.metric ?? {}, value: Number(r.value?.[1] ?? 0) }))
  }

  async range(query: string, startS: number, endS: number, stepS: number): Promise<LokiSeries[]> {
    const body = await this.get('/loki/api/v1/query_range', {
      query, start: String(Math.floor(startS)), end: String(Math.floor(endS)), step: `${Math.max(1, Math.floor(stepS))}s`,
    })
    return (body.data?.result ?? []).map((r) => ({
      metric: r.metric ?? {},
      values: (r.values ?? []).map(([t, v]) => [Number(t), Number(v)] as [number, number]),
    }))
  }
}

let override: LokiClient | null = null

/** The configured client. Throws LokiUnavailableError when LOKI_URL is not set. */
export function lokiClient(): LokiClient {
  if (override) return override
  if (!env.LOKI_URL) throw new LokiUnavailableError('LOKI_URL is not configured')
  return new HttpLokiClient(env.LOKI_URL, env.LOKI_TIMEOUT_MS)
}

/** Test seam. */
export function setLokiClient(client: LokiClient | null): void {
  override = client
}

export const msToNs = (ms: number): string => (BigInt(Math.floor(ms)) * 1_000_000n).toString()
