import type { LokiClient, LokiEntry, LokiRangeParams, LokiSample, LokiSeries } from '../../../audit/query/loki.js'
import { LokiUnavailableError } from '../../../audit/query/loki.js'
import { HashChain } from '../../../audit/v1/chain.js'
import { buildEvent, type AuditV1Input } from '../../../audit/v1/emitter.js'

/** A Loki that records every query and answers from a fixed list of pino audit lines. */
export class FakeLoki implements LokiClient {
  down = false
  queries: string[] = []
  ranges: LokiRangeParams[] = []
  entries: LokiEntry[] = []
  samples: LokiSample[] = []
  series: LokiSeries[] = []
  private fail() {
    if (this.down) throw new LokiUnavailableError('connect ECONNREFUSED')
  }

  async queryRange(p: LokiRangeParams): Promise<LokiEntry[]> {
    this.fail()
    this.queries.push(p.query)
    this.ranges.push(p)
    const start = BigInt(p.startNs)
    const end = BigInt(p.endNs)
    const inRange = this.entries.filter((e) => BigInt(e.ts) >= start && BigInt(e.ts) < end)
    const sorted = [...inRange].sort((a, b) => (BigInt(a.ts) < BigInt(b.ts) ? 1 : -1))
    if (p.direction === 'forward') sorted.reverse()
    return sorted.slice(0, p.limit)
  }

  async instant(query: string): Promise<LokiSample[]> {
    this.fail()
    this.queries.push(query)
    return this.samples
  }

  async range(query: string): Promise<LokiSeries[]> {
    this.fail()
    this.queries.push(query)
    return this.series
  }
}

const chain = new HashChain()

/** One audit line as the pino child writes it (with the logger's own fields around the event). */
export function line(input: Partial<AuditV1Input> & { event: AuditV1Input['event'] }, at: number): LokiEntry {
  const body = buildEvent({ actor: { id: 'actor-1' }, ...input } as AuditV1Input, at)
  const sealed = chain.seal(body)
  const pino = { level: 30, time: at, pid: 1, hostname: 'jinbe-0', component: 'audit', msg: 'audit', ...sealed }
  return { ts: `${BigInt(at) * 1_000_000n}`, line: JSON.stringify(pino), labels: { log_type: 'audit' } }
}

/** Minimal Redis for exports, saved queries and the tail lock. */
export class MemoryRedis {
  kv = new Map<string, string>()
  hashes = new Map<string, Map<string, string>>()
  streams = new Map<string, Array<[string, string[]]>>()
  seq = 0
  async set(key: string, value: string, ...args: Array<string | number>) {
    if (args.includes('NX') && this.kv.has(key)) return null
    this.kv.set(key, value)
    return 'OK'
  }
  async get(key: string) { return this.kv.get(key) ?? null }
  async del(...keys: string[]) { let n = 0; for (const k of keys) if (this.kv.delete(k)) n++; return n }
  async expire() { return 1 }
  async hset(key: string, field: string, value: string) {
    if (!this.hashes.has(key)) this.hashes.set(key, new Map())
    this.hashes.get(key)!.set(field, value)
    return 1
  }
  async hget(key: string, field: string) { return this.hashes.get(key)?.get(field) ?? null }
  async hgetall(key: string) { return Object.fromEntries(this.hashes.get(key) ?? []) }
  async hdel(key: string, field: string) { return this.hashes.get(key)?.delete(field) ? 1 : 0 }
  async xadd(key: string, _id: string, ...fields: string[]) {
    const id = `${++this.seq}-0`
    if (!this.streams.has(key)) this.streams.set(key, [])
    this.streams.get(key)!.push([id, fields])
    return id
  }
  async xrange(key: string) { return this.streams.get(key) ?? [] }
  async xdel(key: string, ...ids: string[]) {
    const s = this.streams.get(key) ?? []
    this.streams.set(key, s.filter(([id]) => !ids.includes(id)))
    return ids.length
  }
}
