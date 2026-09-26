import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// requireSitesApply: `sites:apply`, held only through the global "*" (super_admin). An admin with
// admin:write is refused; OPA unreachable is 503, never 403.

const m = vi.hoisted(() => ({ held: null as string[] | null, env: { DEV_BYPASS_AUTH: false, NODE_ENV: 'test' } }))
vi.mock('../../config/env.js', () => ({ env: m.env }))
vi.mock('../../authz/opa.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../authz/opa.js')>()),
  rights: vi.fn(async () => {
    if (!m.held) throw new Error('OPA is unreachable')
    return { groups: [], roles: [], permissions: m.held }
  }),
}))
vi.mock('../../audit/deny.js', () => ({ denyAudit: vi.fn() }))

import { requireSitesApply } from '../../middleware/require-admin.js'
import { enforcedBy } from '../../policy/declared-routes.js'

const request = () => ({ userContext: { id: 'sub-1', email: 'a@x.test' }, log: { warn: vi.fn(), debug: vi.fn() }, headers: {}, method: 'POST', url: '/x' }) as unknown as FastifyRequest
function reply() {
  const r = { code: 0, body: undefined as unknown, status(c: number) { r.code = c; return r }, send(b: unknown) { r.body = b; return r } }
  return r
}
const run = async () => {
  const r = reply()
  await (requireSitesApply as (q: FastifyRequest, p: FastifyReply) => Promise<unknown>)(request(), r as unknown as FastifyReply)
  return r.code
}

describe('requireSitesApply', () => {
  beforeEach(() => { m.held = null })

  it('publishes sites:apply in the route table', () => {
    expect(enforcedBy(requireSitesApply)).toBe('sites:apply')
  })

  it('lets a holder of "*" through', async () => {
    m.held = ['*', 'admin:write']
    expect(await run()).toBe(0)
  })

  it('lets an explicit sites:apply through', async () => {
    m.held = ['sites:apply']
    expect(await run()).toBe(0)
  })

  it('refuses admin:write alone', async () => {
    m.held = ['admin:read', 'admin:write']
    expect(await run()).toBe(403)
  })

  it('answers 503 when OPA cannot be asked', async () => {
    expect(await run()).toBe(503)
  })
})
