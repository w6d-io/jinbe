import { NotifyError, type EntityEvent, type Notifier, type NotifyResult } from './types.js'

export interface HttpNotifierConfig {
  url: string
  timeoutMs?: number
}

// The receiver's answer is quoted in the failure reason, and no further: it is logged and stored.
const BODY_QUOTE_MAX = 200

export class HttpNotifier implements Notifier {
  readonly name = 'http'
  private readonly url: string
  private readonly timeoutMs: number

  constructor(config: HttpNotifierConfig) {
    this.url = config.url.replace(/\/+$/, '')
    this.timeoutMs = config.timeoutMs ?? 5_000
  }

  async notify(event: EntityEvent): Promise<NotifyResult> {
    const target = `${this.url}/ingest`
    let res: Response
    try {
      res = await fetch(target, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
        signal: AbortSignal.timeout(this.timeoutMs),
      })
    } catch (err) {
      throw new NotifyError(`POST ${printable(target)}: ${networkReason(err, this.timeoutMs)}`)
    }

    if (!res.ok) {
      const body = (await res.text().catch(() => '')).slice(0, BODY_QUOTE_MAX)
      // A 4xx other than timeout / rate limit is the receiver refusing THIS event: the same bytes
      // will be refused again, so it is not retried.
      const permanent = res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429
      throw new NotifyError(`POST ${printable(target)}: HTTP ${res.status}${body ? ` ${body}` : ''}`, { permanent })
    }

    return { acknowledged: true }
  }
}

/** The target without any credentials a URL may carry. */
function printable(target: string): string {
  try {
    const u = new URL(target)
    return `${u.origin}${u.pathname}`
  } catch {
    return '(invalid url)'
  }
}

/** Undici says "fetch failed" and puts what happened in `cause` (ENOTFOUND, ECONNREFUSED, …). */
function networkReason(err: unknown, timeoutMs: number): string {
  if (!(err instanceof Error)) return String(err)
  if (err.name === 'TimeoutError' || err.name === 'AbortError') return `no answer within ${timeoutMs} ms`
  const cause = (err as Error & { cause?: unknown }).cause as { message?: string; code?: string } | undefined
  return cause?.message || cause?.code || err.message
}
