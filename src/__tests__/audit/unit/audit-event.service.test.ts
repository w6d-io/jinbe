import { describe, it, expect, beforeEach, vi } from 'vitest'

// In-memory Redis mock that records xadd MAXLEN args + expire TTLs so the
// fan-out bounds (P0-2) are assertable.
const { redisMock, redisModule } = vi.hoisted(() => {
  class M {
    streams = new Map<string, Array<{ id: string; fields: string[] }>>()
    hashes = new Map<string, Map<string, string>>()
    xaddCalls: Array<{ key: string; maxlen?: string; fields: string[] }> = []
    expireCalls: Array<{ key: string; ttl: number }> = []
    seq = 0
    async xadd(key: string, ...args: string[]) {
      let i = 0
      let maxlen: string | undefined
      if (args[0] === 'MAXLEN') { maxlen = args[2]; i = 3 } // MAXLEN ~ <n>
      const idArg = args[i]; i++
      const fields = args.slice(i)
      const id = idArg === '*' ? `${Date.now()}-${this.seq++}` : idArg
      if (!this.streams.has(key)) this.streams.set(key, [])
      this.streams.get(key)!.push({ id, fields })
      this.xaddCalls.push({ key, maxlen, fields })
      return id
    }
    async expire(key: string, ttl: number) { this.expireCalls.push({ key, ttl: Number(ttl) }); return 1 }
    async xrevrange(key: string, _end: string, _start: string, ...rest: string[]) {
      const arr = (this.streams.get(key) ?? []).slice().reverse()
      let count = arr.length
      const ci = rest.indexOf('COUNT')
      if (ci >= 0) count = Number(rest[ci + 1])
      return arr.slice(0, count).map((e) => [e.id, e.fields] as [string, string[]])
    }
    async xlen(key: string) { return (this.streams.get(key) ?? []).length }
    async hset(key: string, field: string, value: string) {
      if (!this.hashes.has(key)) this.hashes.set(key, new Map())
      this.hashes.get(key)!.set(field, value)
      return 1
    }
    async hgetall(key: string) { const h = this.hashes.get(key); return h ? Object.fromEntries(h) : {} }
    async ping() { return 'PONG' }
    clear() { this.streams.clear(); this.hashes.clear(); this.xaddCalls = []; this.expireCalls = [] }
  }
  const mock = new M()
  return {
    redisMock: mock,
    redisModule: {
      redisClientService: { getClient: () => mock, isHealthy: () => Promise.resolve(true), disconnect: () => Promise.resolve(), isConnected: true },
      getRedisClient: () => mock,
    },
  }
})

vi.mock('../../../services/redis-client.service.js', () => redisModule)

import { auditEventService } from '../../../services/audit-event.service.js'

const MAIN = 'auth:audit:events'

/** Read a stored stream entry's fields as an object. */
function fieldsOf(key: string, index = 0): Record<string, string> {
  const entry = redisMock.streams.get(key)?.[index]
  const out: Record<string, string> = {}
  if (!entry) return out
  for (let i = 0; i < entry.fields.length; i += 2) out[entry.fields[i]] = entry.fields[i + 1]
  return out
}

describe('auditEventService — redaction (P0-3)', () => {
  beforeEach(() => redisMock.clear())

  it('never stores client_secret / recovery_link values', async () => {
    await auditEventService.emit({
      category: 'secret',
      verb: 'create',
      target: 'api_key:svc',
      result: 'applied',
      actor: { email: 'admin@example.com', ip: '1.2.3.4' },
      details: {
        client_secret: 'super-secret-value-abc123',
        recovery_link: 'https://auth/recover?token=zzz999',
        normalField: 'keep-me',
      },
      changes: { resource: 'api_key', changedKeys: ['client_secret', 'name'] },
    })

    const stored = fieldsOf(MAIN)
    const blob = JSON.stringify(stored)
    // No raw secret material anywhere in the serialized entry.
    expect(blob).not.toContain('super-secret-value-abc123')
    expect(blob).not.toContain('zzz999')
    expect(blob).toContain('[redacted]')

    const details = JSON.parse(stored.details)
    expect(details.client_secret).toBe('[redacted]')
    expect(details.recovery_link).toBe('[redacted]')
    expect(details.normalField).toBe('keep-me')

    // A sensitive changedKey name is redacted too.
    const changes = JSON.parse(stored.changes)
    expect(changes.changedKeys).toEqual(['[redacted]', 'name'])
  })
})

describe('auditEventService — changes persistence + read-back', () => {
  beforeEach(() => redisMock.clear())

  it('persists changes.added/removed for a group change and reads them back', async () => {
    await auditEventService.emit({
      category: 'rbac',
      verb: 'update',
      target: 'group:finance',
      result: 'applied',
      actor: { email: 'admin@example.com', ip: '1.2.3.4', sessionId: 'sess-1' },
      changes: { resource: 'group', id: 'finance', added: ['billing:admin'], removed: ['billing:viewer'] },
    })

    const [event] = await auditEventService.query({ limit: 10 })
    expect(event.changes?.added).toEqual(['billing:admin'])
    expect(event.changes?.removed).toEqual(['billing:viewer'])
    // sessionId is projected back (P1-6).
    expect(event.sessionId).toBe('sess-1')
  })
})

describe('auditEventService — fan-out bounds (P0-2)', () => {
  beforeEach(() => redisMock.clear())

  it('does NOT fan out an access.allow event', async () => {
    await auditEventService.emit({
      category: 'access',
      verb: 'allow',
      target: 'GET /api/admin/users',
      result: 'ok',
      actor: { email: 'admin@example.com', ip: '1.2.3.4' },
    })
    // Only the global stream is written — no svc/actor/target keys.
    expect(redisMock.xaddCalls.map((c) => c.key)).toEqual([MAIN])
    expect(redisMock.streams.has('auth:audit:actor:admin@example.com')).toBe(false)
  })

  it('fans a change event to svc + actor keys with MAXLEN 500 and 90d TTL', async () => {
    await auditEventService.emit({
      category: 'rbac',
      kind: 'change',
      verb: 'update',
      target: 'group:finance',
      result: 'applied',
      service: 'billing',
      actor: { email: 'admin@example.com', ip: '1.2.3.4' },
    })

    const keys = redisMock.xaddCalls.map((c) => c.key)
    expect(keys).toContain(MAIN)
    expect(keys).toContain('auth:audit:svc:billing')
    expect(keys).toContain('auth:audit:actor:admin@example.com')

    // Fan-out keys are bounded: MAXLEN 500 + 90-day TTL.
    const fanCalls = redisMock.xaddCalls.filter((c) => c.key !== MAIN)
    expect(fanCalls.length).toBeGreaterThan(0)
    for (const c of fanCalls) expect(c.maxlen).toBe('500')
    const NINETY_DAYS = 90 * 24 * 60 * 60
    for (const e of redisMock.expireCalls) expect(e.ttl).toBe(NINETY_DAYS)
    expect(redisMock.expireCalls.map((e) => e.key)).toEqual(
      expect.arrayContaining(['auth:audit:svc:billing', 'auth:audit:actor:admin@example.com']),
    )
  })

  it('never creates actor:<email> for an unauthenticated actor (per-IP only)', async () => {
    await auditEventService.emit({
      category: 'access',
      kind: 'change',
      verb: 'deny',
      target: 'POST /api/admin/x',
      result: 'denied',
      actor: { email: null, ip: '9.9.9.9' },
    })
    const keys = redisMock.xaddCalls.map((c) => c.key)
    expect(keys).toContain('auth:audit:ip:9.9.9.9')
    expect(keys.some((k) => k.startsWith('auth:audit:actor:'))).toBe(false)
  })
})
