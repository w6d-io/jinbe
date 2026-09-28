import { env } from '../config/env.js'
import { buildOpalDatasourceEntries } from './opal-datasource.js'
import { opalPushes, opalPushLastSuccess } from '../telemetry/metrics.js'

/**
 * Tells opal-server that RBAC data changed, so every OPAL client refetches it into OPA.
 *
 * opal-server reads jinbe's manifest only when a client connects and never refreshes it on its own,
 * so without this push a change made through jinbe reaches OPA only when opal-client restarts (or,
 * since the manifest carries periodic_update_interval, at the next poll). The push is the whole
 * manifest, from the same builder GET /opal-datasource serves, never a per-mutation subset: every
 * client refetches every entry, which is cheap and cannot miss a path a new mutation touches.
 *
 * Bursts coalesce: the first change opens a short window, everything inside it goes out as one push.
 * The request that made the change never waits. A push that fails is retried with backoff and
 * logged once, when the retries run out. Without OPAL_SERVER_URL this does nothing and logs nothing.
 */
export const OPAL_PUSH_WINDOW_MS = 250
export const OPAL_PUSH_BACKOFF_MS = [1_000, 2_000, 4_000, 8_000]
const TIMEOUT_MS = 5_000

class OpalPublisher {
  private timer: ReturnType<typeof setTimeout> | null = null
  private reasons = new Set<string>()
  private running: Promise<void> | null = null
  private again = false

  /** Queue a push for this change. Returns at once. */
  schedule(reason: string): void {
    if (!env.OPAL_SERVER_URL) return
    this.reasons.add(reason)
    if (this.timer) return
    this.timer = setTimeout(() => void this.flush(), OPAL_PUSH_WINDOW_MS)
    this.timer.unref?.()
  }

  /** Push now, skipping the window (startup). Resolves when this push has succeeded or given up. */
  refreshAll(reason: string): Promise<void> {
    if (!env.OPAL_SERVER_URL) return Promise.resolve()
    this.reasons.add(reason)
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
    return this.flush()
  }

  /** Drop pending work. Tests only. */
  reset(): void {
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
    this.reasons.clear()
    this.running = null
    this.again = false
  }

  private flush(): Promise<void> {
    this.timer = null
    // One push at a time; whatever arrives meanwhile goes out right after it.
    if (this.running) {
      this.again = true
      return this.running
    }
    const reason = [...this.reasons].join(',')
    this.reasons.clear()
    const run = this.pushWithRetry(reason).finally(() => {
      if (this.running !== run) return
      this.running = null
      if (this.again) {
        this.again = false
        void this.flush()
      }
    })
    this.running = run
    return run
  }

  private async pushWithRetry(reason: string): Promise<void> {
    let lastErr: unknown
    for (let attempt = 0; attempt <= OPAL_PUSH_BACKOFF_MS.length; attempt++) {
      if (attempt > 0) await sleep(OPAL_PUSH_BACKOFF_MS[attempt - 1])
      try {
        const count = await this.push(reason)
        opalPushes.labels('ok').inc()
        opalPushLastSuccess.set(Date.now() / 1000)
        console.log(`[opal-push] ${count} entries pushed (${reason})`)
        return
      } catch (err) {
        lastErr = err
      }
    }
    opalPushes.labels('failed').inc()
    console.error(
      `[opal-push] Failed after ${OPAL_PUSH_BACKOFF_MS.length + 1} attempts (${reason}); OPA catches up at the next periodic refresh:`,
      lastErr instanceof Error ? lastErr.message : lastErr,
    )
  }

  private async push(reason: string): Promise<number> {
    // A data update entry has no polling interval — that belongs to the manifest only.
    const entries = (await buildOpalDatasourceEntries()).map(({ periodic_update_interval: _, ...entry }) => entry)
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (env.OPAL_SERVER_TOKEN) headers.Authorization = `Bearer ${env.OPAL_SERVER_TOKEN}`
    const res = await fetch(`${env.OPAL_SERVER_URL}/data/config`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ entries, reason }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
    if (!res.ok) throw new Error(`opal-server answered ${res.status}`)
    return entries.length
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export const opalPublisher = new OpalPublisher()
