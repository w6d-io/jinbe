import { env } from '../config/env.js'

/**
 * Instant PromQL queries, as the Home reads them (home-data J5). In-cluster, no auth, like Loki.
 *
 * Optional by design: jinbe's observability is "off unless asked for" (docs/observability.md), so an
 * unset PROMETHEUS_URL is `not configured`, and anything but a clean 2xx — timeout, refused, 5xx — is
 * `PrometheusUnavailableError`, which a tile shows as a source that did not answer. Every query is
 * written by jinbe; nothing from a client reaches one.
 */

export interface PromSample { metric: Record<string, string>; value: number }

export interface PromClient {
  instant(query: string): Promise<PromSample[]>
}

export class PrometheusUnavailableError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message)
    this.name = 'PrometheusUnavailableError'
  }
}

export const PROM_TIMEOUT_MS = 3_000

type PromResponse = { status?: string; data?: { result?: Array<{ metric?: Record<string, string>; value?: [number, string] }> } }

export class HttpPromClient implements PromClient {
  constructor(private readonly baseUrl: string, private readonly timeoutMs = PROM_TIMEOUT_MS) {}

  async instant(query: string): Promise<PromSample[]> {
    const url = `${this.baseUrl.replace(/\/$/, '')}/api/v1/query?${new URLSearchParams({ query })}`
    let res: Response
    try {
      res = await fetch(url, { signal: AbortSignal.timeout(this.timeoutMs) })
    } catch (err) {
      throw new PrometheusUnavailableError(err instanceof Error ? err.message : String(err))
    }
    // The body may echo the query; only the status leaves this function.
    if (!res.ok) throw new PrometheusUnavailableError(`prometheus answered ${res.status}`, res.status)
    const body = (await res.json()) as PromResponse
    if (body.status !== 'success') throw new PrometheusUnavailableError('prometheus answered no data')
    return (body.data?.result ?? []).map((r) => ({ metric: r.metric ?? {}, value: Number(r.value?.[1] ?? NaN) }))
  }
}

let override: PromClient | null = null

/** The configured client, or null when PROMETHEUS_URL is not set. */
export function promClient(): PromClient | null {
  if (override) return override
  return env.PROMETHEUS_URL ? new HttpPromClient(env.PROMETHEUS_URL) : null
}

/** Test seam. */
export function setPromClient(client: PromClient | null): void {
  override = client
}
