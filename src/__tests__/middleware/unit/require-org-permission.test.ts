import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// The one gate of a route of one organisation: OPA's `rbac.decision` for this very request — the
// caller's grants IN THAT ORG (org roles assigned there, or the every-org map). The rule itself is
// opal-policies' (tested against policy-contract.json); jinbe asks and obeys. No super-admin flag,
// no platform holder, no roster.

const ACME = '11111111-1111-1111-1111-111111111111'
const GLOBEX = '22222222-2222-2222-2222-222222222222'
const X = 'x@acme.test'

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))

import { requireOrgPermission } from '../../../middleware/require-org-permission.js'
import { enforcedBy } from '../../../policy/declared-routes.js'
import { decide } from '../../../authz/opa.js'
import { auditEventService } from '../../../services/audit-event.service.js'
import { opaWorld, resetOpaWorld } from '../../helpers/opa-authz-mock.js'

function run(guard: (req: FastifyRequest, rep: FastifyReply) => Promise<unknown>, org: string, user: { id?: string; email?: string; aal?: string } = { id: 'subject-x', email: X, aal: 'aal2' }) {
  const req = {
    userContext: user,
    method: 'GET',
    url: `/api/organizations/${org}/api-keys?page=2`,
    ip: '127.0.0.1',
    headers: {},
    params: { organizationId: org },
    routeOptions: { config: { permission: 'org.keys:read' } },
    log: { warn: vi.fn(), debug: vi.fn() },
  } as unknown as FastifyRequest
  const rep = {
    code: undefined as number | undefined,
    body: undefined as unknown,
    status(c: number) { this.code = c; return this },
    send(b: unknown) { this.body = b; return this },
  }
  return guard(req, rep as unknown as FastifyReply).then(() => rep)
}

const keys = () => requireOrgPermission('org.keys:read')

beforeEach(() => {
  vi.clearAllMocks()
  resetOpaWorld()
})

describe('requireOrgPermission — the org clause for this request', () => {
  it('is marked with the permission it enforces when fixed (published route table)', () => {
    expect(enforcedBy(keys())).toBe('org.keys:read')
  })

  it('401 without an identity, before asking OPA', async () => {
    expect((await run(keys(), ACME, {})).code).toBe(401)
    expect(decide).not.toHaveBeenCalled()
  })

  it('asks rbac.decision about this very request, query string dropped', async () => {
    opaWorld.decide = () => true
    expect((await run(keys(), ACME)).code).toBeUndefined()
    expect(decide).toHaveBeenCalledWith({ email: X, method: 'GET', path: `/api/organizations/${ACME}/api-keys`, aal: 'aal2', client: false })
  })

  it('lets in whoever holds it in THAT org, and refuses (403, audited) whoever holds it only elsewhere', async () => {
    opaWorld.orgPermissions[X] = { [ACME]: ['org.keys:read'] }
    expect((await run(keys(), ACME)).code).toBeUndefined()
    const refused = await run(keys(), GLOBEX)
    expect(refused.code).toBe(403)
    expect(refused.body).toMatchObject({ code: 'permission_required', permission: 'org.keys:read' })
    expect(auditEventService.emit).toHaveBeenCalledWith(expect.objectContaining({ verb: 'deny', reason: 'forbidden:org.keys:read' }))
  })

  it('a platform permission counts for nothing inside an org (OPA decides on org grants only)', async () => {
    opaWorld.permissions[X] = ['orgs:read', 'users:read']
    expect((await run(keys(), ACME)).code).toBe(403)
  })

  it('503, not 403, when OPA cannot be asked', async () => {
    opaWorld.down = true
    expect((await run(keys(), ACME)).code).toBe(503)
  })
})
