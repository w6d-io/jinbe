import { describe, it, expect, beforeEach, vi } from 'vitest'
import { readFileSync, readdirSync } from 'fs'
import { join } from 'path'
import type { FastifyReply, FastifyRequest } from 'fastify'

// AUD-3/AUD-4: one helper writes every guard refusal, and it carries the SUBJECT id — the trail was
// keyed by address, and ten copies of the same object literal disagreed about what they recorded.

const h = vi.hoisted(() => ({ emit: vi.fn(async () => '1-0'), rights: vi.fn() }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../../authz/opa.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../authz/opa.js')>()),
  rights: h.rights,
}))

import { denyAudit } from '../../../audit/deny.js'
import { requireAdmin } from '../../../middleware/require-admin.js'
import { requireAuth } from '../../../middleware/require-auth.js'

const SUBJECT = '3f2a8c1e-0000-4000-8000-00000000abcd'

function request(over: Record<string, unknown> = {}): FastifyRequest {
  return {
    method: 'PUT',
    url: '/api/admin/users/42?x=1',
    ip: '10.1.2.3',
    headers: { 'user-agent': 'Firefox', 'x-request-id': 'req-7', host: 'api.example.com' },
    userContext: { id: SUBJECT, email: 'someone@example.com', name: 'S', sessionId: 'sess-1' },
    log: { warn: vi.fn(), debug: vi.fn(), info: vi.fn(), error: vi.fn() },
    ...over,
  } as unknown as FastifyRequest
}

function reply() {
  const r = { code: 0, status(c: number) { r.code = c; return r }, send() { return r }, header() { return r } }
  return r as unknown as FastifyReply & { code: number }
}

describe('denyAudit()', () => {
  beforeEach(() => h.emit.mockClear())

  it('writes one access.denied event keyed on the subject id, with the request id and the route', () => {
    denyAudit(request(), 'not_admin', { statusCode: 403 })
    expect(h.emit).toHaveBeenCalledTimes(1)
    const [event] = h.emit.mock.calls[0] as unknown as [Record<string, any>]
    expect(event).toMatchObject({
      category: 'access', verb: 'deny', result: 'denied', reason: 'not_admin', v1Event: 'access.denied',
      method: 'PUT', path: '/api/admin/users/42', target: 'PUT /api/admin/users/42', statusCode: 403,
      requestId: 'req-7',
    })
    expect(event.actor).toMatchObject({ id: SUBJECT, ip: '10.1.2.3', ua: 'Firefox', sessionId: 'sess-1' })
  })

  it('records an anonymous caller without inventing an id', () => {
    denyAudit(request({ userContext: undefined }), 'unauthenticated')
    const [event] = h.emit.mock.calls[0] as unknown as [Record<string, any>]
    expect(event.actor.id).toBeNull()
    expect(event.actor.email).toBeNull()
  })

  it('never throws, even when the emitter rejects', async () => {
    h.emit.mockRejectedValueOnce(new Error('down'))
    expect(() => denyAudit(request(), 'x')).not.toThrow()
    await new Promise((r) => setImmediate(r))
  })
})

describe('the guards use it', () => {
  beforeEach(() => { h.emit.mockClear(); h.rights.mockReset() })

  it('requireAdmin refuses with the subject id on the event', async () => {
    h.rights.mockResolvedValue({ groups: [], roles: [], permissions: [] })
    const r = reply()
    await requireAdmin(request(), r)
    expect(r.code).toBe(403)
    expect(h.emit).toHaveBeenCalledTimes(1)
    expect((h.emit.mock.calls[0] as unknown as [Record<string, any>])[0]).toMatchObject({ v1Event: 'access.denied', reason: 'not_admin', actor: { id: SUBJECT } })
  })

  it('requireAuth refuses an anonymous caller through the same helper', async () => {
    const r = reply()
    await requireAuth(request({ userContext: undefined, url: '/api/clusters' }), r)
    expect(r.code).toBe(401)
    expect((h.emit.mock.calls[0] as unknown as [Record<string, any>])[0]).toMatchObject({ v1Event: 'access.denied', reason: 'unauthenticated' })
  })

  it('no guard builds its own deny event any more (static)', () => {
    const root = join(__dirname, '../../..')
    const files = [
      ...readdirSync(join(root, 'middleware')).map((f) => join(root, 'middleware', f)),
      join(root, 'routes/directory.routes.ts'),
    ]
    const offenders = files.filter((f) => /verb:\s*'deny'/.test(readFileSync(f, 'utf8')))
    expect(offenders).toEqual([])
  })
})
