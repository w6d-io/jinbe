import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// Story 6: an org admin manages their own organisation's people without holding a group that grants
// in it. OPA names them — on that org's roster AND a member of it (`manageable_orgs`) — and decides
// the request exactly as the gateway does (`rbac.decision`).

const ACME = '11111111-1111-1111-1111-111111111111'
const GLOBEX = '22222222-2222-2222-2222-222222222222'
const OLIVIA = 'olivia@acme.test'

const state = vi.hoisted(() => ({
  env: { DEV_BYPASS_AUTH: false, NODE_ENV: 'test' },
}))

vi.mock('../../../config/index.js', () => ({ env: state.env }))
vi.mock('../../../config/env.js', () => ({ env: state.env }))
vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))

import { requireServiceAdmin, requireServicePermission } from '../../../middleware/require-service-admin.js'
import { requireManageableOrg } from '../../../middleware/require-manageable-org.js'
import { manageableOrgs } from '../../../authz/opa.js'
import { opaWorld, resetOpaWorld } from '../../helpers/opa-authz-mock.js'

function request(organizationId: string): FastifyRequest {
  return {
    userContext: { id: 'subject-olivia', email: OLIVIA },
    method: 'GET',
    url: `/api/organizations/${organizationId}/users`,
    ip: '127.0.0.1',
    headers: {},
    params: { organizationId },
    log: { warn: vi.fn(), debug: vi.fn(), info: vi.fn() },
  } as unknown as FastifyRequest
}

function reply() {
  const r = {
    code: undefined as number | undefined,
    body: undefined as unknown,
    status: vi.fn(function (this: typeof r, code: number) {
      this.code = code
      return this
    }),
    send: vi.fn(function (this: typeof r, body: unknown) {
      this.body = body
      return this
    }),
  }
  return r
}

/** The org-user chain exactly as the plugin registers it. */
async function chain(organizationId: string) {
  const req = request(organizationId)
  const rep = reply()
  await requireServiceAdmin('organizationId', { orgAdmin: true })(req, rep as unknown as FastifyReply)
  if (rep.code === undefined) await requireManageableOrg()(req, rep as unknown as FastifyReply)
  return { req, rep }
}

describe('requireServiceAdmin — the org-admin path', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetOpaWorld()
  })

  it('admits a roster admin who is a member, with no group granting in the org', async () => {
    opaWorld.manageable[OLIVIA] = [ACME]
    opaWorld.members[OLIVIA] = [ACME]

    const { req, rep } = await chain(ACME)

    expect(rep.code).toBeUndefined()
    expect(req.rbacInfo?.permissions).toContain('org:manage_users')
  })

  it('refuses the roster admin of Acme on Globex, even as a Globex member', async () => {
    opaWorld.manageable[OLIVIA] = [ACME]
    opaWorld.members[OLIVIA] = [ACME, GLOBEX]

    const { rep } = await chain(GLOBEX)

    expect(rep.code).toBe(403)
  })

  it('refuses when OPA does not list the org — a roster entry without membership is not enough', async () => {
    // manageable_orgs is roster ∧ membership, computed by OPA: a non-member is simply not listed.
    opaWorld.manageable[OLIVIA] = []
    opaWorld.members[OLIVIA] = []

    const { rep } = await chain(ACME)

    expect(rep.code).toBe(403)
  })

  it('grants member management only — never a wildcard, never group assignment', async () => {
    opaWorld.manageable[OLIVIA] = [ACME]
    opaWorld.members[OLIVIA] = [ACME]

    const { req } = await chain(ACME)

    expect(req.rbacInfo?.permissions).not.toContain('*')
    const rep = reply()
    await requireServicePermission('users:assign_group')(req, rep as unknown as FastifyReply)
    expect(rep.code).toBe(403)
  })

  it('keeps what groups give alongside the org-admin rights', async () => {
    opaWorld.manageable[OLIVIA] = [ACME]
    opaWorld.members[OLIVIA] = [ACME]
    opaWorld.permissions[OLIVIA] = ['clusters:read']

    const { req } = await chain(ACME)

    expect(req.rbacInfo?.permissions).toEqual(
      expect.arrayContaining(['clusters:read', 'org:manage_users']),
    )
  })

  it('answers 503, not 403, when OPA cannot be asked', async () => {
    opaWorld.down = true

    const { rep } = await chain(ACME)

    expect(rep.code).toBe(503)
  })

  it('is opt-in: a gate built without it never asks manageable_orgs nor adds the org-admin set', async () => {
    opaWorld.manageable[OLIVIA] = [ACME]
    opaWorld.members[OLIVIA] = [ACME]
    const req = request(ACME)
    const rep = reply()

    await requireServiceAdmin()(req, rep as unknown as FastifyReply)

    expect(manageableOrgs).not.toHaveBeenCalled()
    expect(req.rbacInfo?.permissions).toEqual([])
  })
})
