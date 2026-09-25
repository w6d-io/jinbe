import { describe, it, expect, beforeEach, vi } from 'vitest'

const mockEnv = vi.hoisted(() => ({
  env: {
    LOG_LEVEL: 'error',
    NODE_ENV: 'test',
    AUDIT_HMAC_KEY: 'k'.repeat(40) as string | undefined,
    AUDIT_OUTBOX_STREAM: 'auth:audit:outbox',
    K8S_SA_EMAIL_DOMAIN: 'serviceaccount.cluster.local',
  },
}))
vi.mock('../../../config/env.js', () => mockEnv)
vi.mock('../../../config/index.js', () => mockEnv)
vi.mock('../../../services/redis-client.service.js', () => ({ getRedisClient: () => ({}) }))

import { register } from 'prom-client'
import { AuditV1Emitter, type AuditEventV1, type AuditOutbox } from '../../../audit/v1/emitter.js'
import { auditEventV1Schema } from '../../../audit/v1/schema.js'
import { HashChain, verifyChain } from '../../../audit/v1/chain.js'
import { uuidv7 } from '../../../audit/v1/ids.js'
import { ipNet } from '../../../audit/v1/pseudonym.js'

class MemoryOutbox implements AuditOutbox {
  rows: AuditEventV1[] = []
  fail = false
  async append(event: AuditEventV1) {
    if (this.fail) throw new Error('redis down')
    this.rows.push(event)
    return `${this.rows.length}-0`
  }
}

function setup() {
  const lines: AuditEventV1[] = []
  const outbox = new MemoryOutbox()
  const emitter = new AuditV1Emitter({ write: (e) => lines.push(e), outbox, chain: new HashChain() })
  return { lines, outbox, emitter }
}

const ADMIN = { id: '3f2a8c1e-0000-4000-8000-000000000001', email: 'admin@example.com', name: 'Ada Admin', ip: '10.89.1.77', ua: 'Mozilla/5.0 Chrome/120', sessionId: 'sess-secret-1' }

async function failures(sink: string): Promise<number> {
  const m = (await register.getMetricsAsJSON()).find((x) => x.name === 'jinbe_audit_v1_failures_total')
  return (m?.values as Array<{ value: number; labels: Record<string, unknown> }> | undefined)?.find((v) => v.labels.sink === sink)?.value ?? 0
}

describe('audit/v1 — schema and ids (AUD-1)', () => {
  it('emits a schema-valid line with log_type=audit and a uuidv7 event_id', async () => {
    const { lines, emitter } = setup()
    await emitter.emit({ event: 'org.grants.changed', actor: ADMIN, target: { type: 'user', id: 'target-uuid' }, org_id: 'org-1', request_id: 'req-1' })
    expect(lines).toHaveLength(1)
    const e = lines[0]
    expect(auditEventV1Schema.safeParse(e).success).toBe(true)
    expect(e).toMatchObject({ log_type: 'audit', schema: 'audit/v1', event: 'org.grants.changed', category: 'authz', action: 'update', result: 'success', org_id: 'org-1', request_id: 'req-1', source: 'jinbe' })
    expect(e.event_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    expect(new Date(e.ts).toISOString()).toBe(e.ts)
  })

  it('uuidv7 sorts by creation time', () => {
    const a = uuidv7()
    const b = uuidv7(Date.now() + 5)
    expect(a < b).toBe(true)
  })

  it('refuses an event type that is not in the catalog', async () => {
    const { lines, emitter } = setup()
    const before = await failures('schema')
    await emitter.emit({ event: 'made.up' as never, actor: ADMIN })
    expect(lines).toHaveLength(0)
    expect(await failures('schema')).toBe(before + 1)
  })
})

describe('audit/v1 — hash chain (AUD-1)', () => {
  it('chains every event of the process and detects a tampered line', async () => {
    const { lines, emitter } = setup()
    for (const event of ['user.created', 'user.updated', 'user.deleted'] as const) {
      await emitter.emit({ event, actor: ADMIN, target: { type: 'user', id: 'u-1' } })
    }
    expect(lines.map((l) => l.seq)).toEqual([1, 2, 3])
    expect(lines[1].prev_hash).toBe(lines[0].hash)
    expect(verifyChain(lines)).toEqual({ ok: true })

    const tampered = lines.map((l) => ({ ...l }))
    tampered[1] = { ...tampered[1], result: 'denied' }
    expect(verifyChain(tampered)).toEqual({ ok: false, at: 1 })

    const dropped = [lines[0], lines[2]]
    expect(verifyChain(dropped)).toEqual({ ok: false, at: 1 })
  })
})

describe('audit/v1 — pseudonymisation (AUD-5)', () => {
  it('carries the actor id, a truncated IP and HMACs — never an email, a name, the IP or the session id', async () => {
    const { lines, emitter } = setup()
    await emitter.emit({
      event: 'user.updated',
      actor: ADMIN,
      target: { type: 'user', id: null, email: 'target@example.com' },
      changes: { resource: 'user', summary: 'renamed target@example.com', added: ['bob@example.com'] },
    })
    const e = lines[0]
    const text = JSON.stringify(e)
    expect(e.actor).toMatchObject({ type: 'user', id: ADMIN.id, ip_net: '10.89.1.0/24', ua_family: 'Chrome' })
    expect(e.actor.ip_hmac).toMatch(/^hmac-sha256:[0-9a-f]{32}$/)
    expect(e.actor.session_id_hash).toMatch(/^hmac-sha256:/)
    expect(e.target?.identifier_hmac).toMatch(/^hmac-sha256:/)
    expect(text).not.toContain('@')
    expect(text).not.toContain('Ada Admin')
    expect(text).not.toContain('10.89.1.77')
    expect(text).not.toContain('sess-secret-1')
  })

  it('truncates IPv4, IPv4-mapped and IPv6 addresses', () => {
    expect(ipNet('192.168.4.9')).toBe('192.168.4.0/24')
    expect(ipNet('::ffff:192.168.4.9')).toBe('192.168.4.0/24')
    expect(ipNet('2001:db8:abcd:12::1')).toBe('2001:db8:abcd::/48')
    expect(ipNet('not-an-ip')).toBeUndefined()
  })

  it('leaves the HMAC fields out when no key is configured', async () => {
    mockEnv.env.AUDIT_HMAC_KEY = undefined
    try {
      const { lines, emitter } = setup()
      await emitter.emit({ event: 'user.updated', actor: ADMIN })
      expect(lines[0].actor.ip_hmac).toBeUndefined()
      expect(lines[0].actor.ip_net).toBe('10.89.1.0/24')
    } finally {
      mockEnv.env.AUDIT_HMAC_KEY = 'k'.repeat(40)
    }
  })

  it('types system and anonymous actors', async () => {
    const { lines, emitter } = setup()
    await emitter.emit({ event: 'site.roles_repaired', actor: { email: 'system' } })
    await emitter.emit({ event: 'access.denied', result: 'denied', reason: 'unauthenticated', actor: { ip: '1.2.3.4' } })
    expect(lines[0].actor).toMatchObject({ type: 'system', id: null })
    expect(lines[1].actor).toMatchObject({ type: 'anonymous', id: null })
  })
})

describe('audit/v1 — durable outbox (AUD-1b)', () => {
  beforeEach(() => vi.clearAllMocks())

  it('keeps the event in the outbox when the log sink fails', async () => {
    const outbox = new MemoryOutbox()
    const emitter = new AuditV1Emitter({ write: () => { throw new Error('stdout closed') }, outbox, chain: new HashChain() })
    const before = await failures('log')
    const event = await emitter.emit({ event: 'apikey.created', actor: ADMIN, target: { type: 'oauth2_client', id: 'c-1' } })
    expect(event).not.toBeNull()
    expect(outbox.rows).toHaveLength(1)
    expect(outbox.rows[0].event_id).toBe(event!.event_id)
    expect(await failures('log')).toBe(before + 1)
  })

  it('still writes the line when the outbox is down, and counts it', async () => {
    const { lines, outbox, emitter } = setup()
    outbox.fail = true
    const before = await failures('outbox')
    await emitter.emit({ event: 'apikey.revoked', actor: ADMIN })
    expect(lines).toHaveLength(1)
    expect(await failures('outbox')).toBe(before + 1)
  })
})
