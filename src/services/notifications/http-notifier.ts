import type { EntityEvent, Notifier, NotifyResult } from './types.js'

export interface HttpNotifierConfig {
  url: string
  timeoutMs?: number
}

export class HttpNotifier implements Notifier {
  readonly name = 'http'
  private readonly url: string
  private readonly timeoutMs: number

  constructor(config: HttpNotifierConfig) {
    this.url = config.url.replace(/\/+$/, '')
    this.timeoutMs = config.timeoutMs ?? 5_000
  }

  async notify(event: EntityEvent): Promise<NotifyResult> {
    const res = await fetch(`${this.url}/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(this.timeoutMs),
    })

    if (!res.ok) {
      const body = await res.text().catch(() => '')
      throw new Error(`HTTP ${res.status}: ${body}`)
    }

    return { acknowledged: true }
  }
}
