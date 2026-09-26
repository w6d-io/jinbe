import { describe, it, expect, beforeEach, vi } from 'vitest'
import Fastify from 'fastify'

// AU-2: every mutating route in the published route table maps to an audit/v1 catalog event (or
// says, in words, why it writes nothing worth one). And the routes that had no emit at all — the
// infrastructure CRUD — get exactly one event per successful command from the same table.

const h = vi.hoisted(() => ({ emit: vi.fn(async () => '1-0') }))

import { AUDIT_EVENTS } from '../../../audit/v1/catalog.js'
import { WRITE_ROUTE_AUDIT, auditRouteWrite, MUTATING } from '../../../audit/route-events.js'
import { declaredRoutes, resetDeclaredRoutes } from '../../../policy/declared-routes.js'
import { auditEventService } from '../../../services/audit-event.service.js'

describe('AU-2 — every write route maps to a catalog event', () => {
  it('covers the running service\'s route table with no unmapped and no stale rows', async () => {
    process.env.NODE_ENV = 'development'
    process.env.DEV_BYPASS_AUTH = 'true'
    process.env.ENCRYPTION_KEY = 'x'.repeat(32)
    process.env.DEV_USER_EMAIL = 'dev@localhost.io'
    resetDeclaredRoutes()
    const { buildServer } = await import('../../../server.js')
    const app = await buildServer()
    try {
      const writes = declaredRoutes().filter((r) => (MUTATING as readonly string[]).includes(r.method)).map((r) => `${r.method} ${r.path}`)
      expect(writes.length).toBeGreaterThan(60)
      const unmapped = writes.filter((k) => !(k in WRITE_ROUTE_AUDIT))
      expect(unmapped).toEqual([])
      const stale = Object.keys(WRITE_ROUTE_AUDIT).filter((k) => !writes.includes(k))
      expect(stale).toEqual([])
    } finally {
      await app.close()
    }
  }, 30_000)

  it('names only catalog keys, and every exemption gives a reason', () => {
    for (const [route, entry] of Object.entries(WRITE_ROUTE_AUDIT)) {
      if ('exempt' in entry) {
        expect(entry.exempt.length, route).toBeGreaterThan(15)
        continue
      }
      for (const e of [entry.event].flat()) expect(Object.keys(AUDIT_EVENTS), route).toContain(e)
    }
  })

  it('the infrastructure CRUD, which had no emit, is written by the route table', () => {
    for (const k of ['POST /api/clusters', 'PUT /api/clusters/:id', 'DELETE /api/clusters/:id', 'POST /api/clusters/:id/databases',
      'PUT /api/databases/:id', 'DELETE /api/databases/:id', 'POST /api/clusters/:id/backups', 'DELETE /api/backups/:id',
      'POST /api/clusters/:clusterId/jobs', 'POST /api/databases/:id/api', 'PUT /api/backup-items/:id']) {
      expect(WRITE_ROUTE_AUDIT[k], k).toMatchObject({ emit: 'route' })
    }
  })
})

describe('auditRouteWrite (onSend)', () => {
  beforeEach(() => {
    h.emit.mockClear()
    vi.spyOn(auditEventService, 'emit').mockImplementation(h.emit as never)
  })

  async function app() {
    const f = Fastify()
    f.addHook('onRequest', async (request) => {
      request.userContext = { id: 'subj-1', email: 'a@example.com', name: 'A' }
    })
    f.addHook('onSend', auditRouteWrite)
    f.post('/api/clusters', async (request, reply) => {
      const body = request.body as { fail?: boolean }
      if (body?.fail) return reply.status(400).send({ error: 'Bad Request' })
      return reply.status(201).send({ id: 'cluster-9', name: 'c' })
    })
    f.delete('/api/clusters/:id', async (_r, reply) => reply.status(204).send())
    f.post('/api/admin/users', async () => ({ id: 'u1' })) // emitted by its handler: the hook stays out
    await f.ready()
    return f
  }

  it('one successful create → exactly one event, with the new id as target', async () => {
    const f = await app()
    const res = await f.inject({ method: 'POST', url: '/api/clusters', payload: {} })
    expect(res.statusCode).toBe(201)
    await new Promise((r) => setImmediate(r))
    expect(h.emit).toHaveBeenCalledTimes(1)
    expect((h.emit.mock.calls[0] as unknown as [Record<string, any>])[0]).toMatchObject({
      v1Event: 'infra.cluster.created', targetType: 'cluster', targetId: 'cluster-9', actor: { id: 'subj-1' }, result: 'applied',
    })
  })

  it('a refused or failed command writes nothing', async () => {
    const f = await app()
    await f.inject({ method: 'POST', url: '/api/clusters', payload: { fail: true } })
    await new Promise((r) => setImmediate(r))
    expect(h.emit).not.toHaveBeenCalled()
  })

  it('takes the target from the path parameter on update/delete', async () => {
    const f = await app()
    await f.inject({ method: 'DELETE', url: '/api/clusters/abc' })
    await new Promise((r) => setImmediate(r))
    expect((h.emit.mock.calls[0] as unknown as [Record<string, any>])[0]).toMatchObject({ v1Event: 'infra.cluster.deleted', targetId: 'abc' })
  })

  it('leaves the routes whose handler emits alone — never two events for one command', async () => {
    const f = await app()
    await f.inject({ method: 'POST', url: '/api/admin/users', payload: {} })
    await new Promise((r) => setImmediate(r))
    expect(h.emit).not.toHaveBeenCalled()
  })
})
