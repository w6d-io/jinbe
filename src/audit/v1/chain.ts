import { createHash } from 'crypto'
import { uuidv7 } from './ids.js'

/**
 * Per-process hash chain over audit/v1 events.
 *
 * Every event carries `chain_id` (one per process start), `seq` (1, 2, 3 …), the previous event's
 * hash and its own: sha256 over the previous hash and the canonical JSON of the event without its
 * `hash`. Removing, reordering or editing a line breaks every hash after it. The hourly checkpoint
 * (AUD-7) writes the last hash to the Object-Lock bucket, which is what makes rewriting the whole
 * tail detectable too.
 */

export const GENESIS = 'sha256:genesis'

/** JSON with keys sorted at every depth, and `undefined` dropped — the bytes that are hashed. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map((v) => (v === undefined ? 'null' : canonical(v))).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`
}

export function hashLink(prevHash: string, body: object): string {
  return `sha256:${createHash('sha256').update(prevHash).update('\n').update(canonical(body)).digest('hex')}`
}

type Linked = { chain_id: string; seq: number; prev_hash: string; hash: string }

export class HashChain {
  readonly chainId = uuidv7()
  private seq = 0
  private prev = GENESIS

  seal<T extends object>(body: T): T & Linked {
    const linked = { ...body, chain_id: this.chainId, seq: this.seq + 1, prev_hash: this.prev }
    const hash = hashLink(this.prev, linked)
    this.seq += 1
    this.prev = hash
    return { ...linked, hash }
  }
}

/**
 * Verifies consecutive events of ONE chain, starting anywhere. `at` is the index of the first event
 * that does not follow from the one before it (or whose own hash is wrong).
 */
export function verifyChain(events: Array<Record<string, unknown> & Linked>): { ok: true } | { ok: false; at: number } {
  for (let i = 0; i < events.length; i++) {
    const { hash, ...rest } = events[i]
    if (hashLink(rest.prev_hash, rest) !== hash) return { ok: false, at: i }
    if (i > 0) {
      const prev = events[i - 1]
      if (rest.prev_hash !== prev.hash || rest.seq !== prev.seq + 1 || rest.chain_id !== prev.chain_id) return { ok: false, at: i }
    }
  }
  return { ok: true }
}
