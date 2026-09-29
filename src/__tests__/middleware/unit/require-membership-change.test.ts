import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// PUT /api/admin/users/:email/groups: removing only needs groups.members:revoke; adding anybody to
// anything needs groups.members:write and a second factor proven within 15 minutes.

const m = vi.hoisted(() => ({ held: [] as string[], current: ['users', 'staff-support'] as string[] }))
vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../audit/deny.js', () => ({ denyAudit: vi.fn() }))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: { findByEmail: vi.fn(async () => ({ id: 'bob-id' })) } }))
vi.mock('../../../services/organisation-store.js', () => ({ groupsForSubjects: vi.fn(async () => new Map([['bob-id', m.current]])) }))

import { requireMembershipChange } from '../../../middleware/require-membership-change.js'
import { enforcedBy } from '../../../policy/declared-routes.js'
import { opaWorld, resetOpaWorld } from '../../helpers/opa-authz-mock.js'

const request = (groups: string[], fresh = false) => ({
  params: { email: 'bob@x.io' },
  body: { groups },
  userContext: { id: 'ann-id', email: 'ann@x.io', authVia: 'session', aal: fresh ? 'aal2' : 'aal1', secondFactorAt: fresh ? new Date(Date.now() - 60_000) : null },
  log: { warn: vi.fn() },
  headers: {},
}) as unknown as FastifyRequest<{ Params: { email: string }; Body: { groups?: unknown } }>
function reply() {
  const r = { code: 0, sent: false, body: undefined as unknown, status(c: number) { r.code = c; return r }, send(b: unknown) { r.body = b; r.sent = true; return r } }
  return r
}
const run = async (groups: string[], fresh = false) => {
  const r = reply()
  await requireMembershipChange(request(groups, fresh), r as unknown as FastifyReply)
  return r
}

beforeEach(() => {
  resetOpaWorld()
  m.current = ['users', 'staff-support']
})

describe('requireMembershipChange', () => {
  it('declares the lesser permission for the route table', () => {
    expect(enforcedBy(requireMembershipChange)).toBe('groups.members:revoke')
  })

  it('removing only: groups.members:revoke, no step-up', async () => {
    opaWorld.permissions['ann@x.io'] = ['groups.members:revoke']
    expect((await run(['users'])).code).toBe(0)
  })

  it('adding: refused with revoke alone', async () => {
    opaWorld.permissions['ann@x.io'] = ['groups.members:revoke']
    const r = await run(['users', 'staff-support', 'staff-ops'], true)
    expect(r.code).toBe(403)
    expect((r.body as { message: string }).message).toContain('groups.members:write')
  })

  it('adding: groups.members:write and a recent second factor', async () => {
    opaWorld.permissions['ann@x.io'] = ['groups.members:write']
    expect((await run(['users', 'staff-ops'])).code).toBe(422)
    expect((await run(['users', 'staff-ops'], true)).code).toBe(0)
  })

  it('holding neither: refused before the target is looked up', async () => {
    const r = await run(['users'])
    expect(r.code).toBe(403)
  })
})
