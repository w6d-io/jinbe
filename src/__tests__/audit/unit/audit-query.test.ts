import { describe, it, expect, beforeEach, vi } from 'vitest'
import Fastify from 'fastify'

// A Redis stream mock that honours XREVRANGE bounds (inclusive, `(` exclusive, `+`/`-`) and COUNT,
// so paging and scan budgets behave as they do against Redis.
const { redisMock } = vi.hoisted(() => {
  const cmp = (a: string, b: string) => {
    const [am, as] = a.split('-').map(Number)
    const [bm, bs] = b.split('-').map(Number)
    return am - bm || as - bs
  }
  class M {
    streams = new Map<string, Array<{ id: string; fields: string[] }>>()
    ms = 1_700_000_000_000
    async xadd(key: string, ...args: string[]) {
      const i = args[0] === 'MAXLEN' ? 3 : 0
      const id = `${this.ms++}-0`
      if (!this.streams.has(key)) this.streams.set(key, [])
      this.streams.get(key)!.push({ id, fields: args.slice(i + 1) })
      return id
    }
    async expire() { return 1 }
    async hset() { return 1 }
    async xlen(key: string) { return (this.streams.get(key) ?? []).length }
    async xrevrange(key: string, end: string, start: string, ...rest: string[]) {
      const count = rest[0] === 'COUNT' ? Number(rest[1]) : Infinity
      const upper = (id: string) => end === '+' || (end.startsWith('(') ? cmp(id, end.slice(1)) < 0 : cmp(id, end) <= 0)
      const lower = (id: string) => start === '-' || (start.startsWith('(') ? cmp(id, start.slice(1)) > 0 : cmp(id, start) >= 0)
      return (this.streams.get(key) ?? []).filter((e) => upper(e.id) && lower(e.id)).reverse().slice(0, count)
        .map((e) => [e.id, e.fields] as [string, string[]])
    }
    clear() { this.streams.clear() }
  }
  return { redisMock: new M() }
})

vi.mock('../../../services/redis-client.service.js', () => ({ getRedisClient: () => redisMock }))
vi.mock('../../../middleware/require-admin.js', () => ({ requireAdmin: vi.fn(async () => undefined) }))

import { auditEventService } from '../../../services/audit-event.service.js'
import { auditRoutes } from '../../../routes/audit.routes.js'
import { auditLog } from '../../../audit/v1/index.js'

auditLog.useSinks({ write: () => {}, outbox: { append: async () => '' } })

async function app() {
  const fastify = Fastify()
  await fastify.register(auditRoutes, { prefix: '/api/admin/audit' })
  await fastify.ready()
  return fastify
}

async function events(url: string) {
  const res = await (await app()).inject({ method: 'GET', url: `/api/admin/audit/events${url}` })
  expect(res.statusCode).toBe(200)
  return res.json() as { events: Array<{ id: string; kind: string; target: string }>; nextCursor: string | null }
}

const actor = { email: 'admin@example.com', id: 'admin-uuid' }

async function seed(system: number, change: number) {
  for (let i = 0; i < system; i++) {
    await auditEventService.emit({ category: 'system', kind: 'system', verb: 'sync', target: `job:${i}`, result: 'ok', actor })
  }
  for (let i = 0; i < change; i++) {
    await auditEventService.emit({ category: 'rbac', verb: 'update', target: `group:g${i}`, result: 'applied', actor })
  }
}

describe('audit query — filtering does not depend on limit (AUD-0c)', () => {
  beforeEach(() => redisMock.clear())

  it('kind=system&limit=2 returns 2 even when the matches are older than limit*8 newer rows', async () => {
    await seed(5, 40)
    const page = await events('?kind=system&limit=2')
    expect(page.events).toHaveLength(2)
    expect(page.events.every((e) => e.kind === 'system')).toBe(true)
    expect(page.nextCursor).not.toBeNull()
  })

  it('pages to the end with an honest nextCursor', async () => {
    await seed(5, 40)
    const seen: string[] = []
    let cursor: string | null = null
    let pages = 0
    do {
      const page = await events(`?kind=system&limit=2${cursor ? `&cursor=${cursor}` : ''}`)
      seen.push(...page.events.map((e) => e.target))
      cursor = page.nextCursor
      pages++
    } while (cursor && pages < 10)
    expect(seen).toEqual(['job:4', 'job:3', 'job:2', 'job:1', 'job:0'])
    expect(pages).toBe(3)
  })

  it('answers nextCursor=null when the window holds no more matches', async () => {
    await seed(2, 10)
    const page = await events('?kind=system&limit=2')
    expect(page.events).toHaveLength(2)
    expect(page.nextCursor).toBeNull()
  })
})

describe('audit query — the "done to them" trail (AUD-0c)', () => {
  beforeEach(() => redisMock.clear())

  it('target=user:<email> (what the console sends) finds events done to that user', async () => {
    await auditEventService.emit({
      type: 'user.groups_changed',
      actor,
      target: { type: 'user', id: 'bob-uuid' },
      details: { targetEmail: 'bob@example.com', oldGroups: [], newGroups: ['editors'] },
    })
    const page = await events(`?target=${encodeURIComponent('user:bob@example.com')}`)
    expect(page.events).toHaveLength(1)
  })

  it('target=user:<id> finds them too, so the trail survives an email change', async () => {
    await auditEventService.emit({
      type: 'user.groups_changed',
      actor,
      target: { type: 'user', id: 'bob-uuid' },
      details: { targetEmail: 'bob@example.com', oldGroups: [], newGroups: ['editors'] },
    })
    const page = await events('?target=user:bob-uuid')
    expect(page.events).toHaveLength(1)
  })
})
