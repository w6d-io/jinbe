import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// Story 6: an org admin manages their own organisation's people without holding a group that grants
// in it. The roster (and the directory's `org_admin` role) names them; the gate used to read only
// what groups give, so a roster admin reached jinbe through the gateway and was refused there.

const ACME = '11111111-1111-1111-1111-111111111111'
const GLOBEX = '22222222-2222-2222-2222-222222222222'

const state = vi.hoisted(() => ({
  env: { DEV_BYPASS_AUTH: false, NODE_ENV: 'test', ORGANISATION_SOURCE: 'directory' },
  held: { groups: [] as string[], roles: [] as string[], permissions: [] as string[] },
  rosters: {} as Record<string, string[]>,
  memberOf: [] as string[],
  directoryRoles: {} as Record<string, { subjectId: string; role: string }[]>,
}))

vi.mock('../../../config/index.js', () => ({ env: state.env }))
vi.mock('../../../config/env.js', () => ({ env: state.env }))
vi.mock('../../../services/authorization-model.service.js', () => ({
  rightsOf: vi.fn(async () => state.held),
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getOrgAdmins: vi.fn(async (org: string) => state.rosters[org] ?? []),
  },
}))
vi.mock('../../../services/caller-organisations.js', () => ({
  callerOrganisations: vi.fn(async () => state.memberOf),
}))
vi.mock('../../../services/organisation-store.js', () => ({
  organisationStoreConfigured: vi.fn(() => true),
  membersOf: vi.fn(async (org: string) => state.directoryRoles[org] ?? []),
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))

import { requireServiceAdmin, requireServicePermission } from '../../../middleware/require-service-admin.js'
import { requireManageableOrg } from '../../../middleware/require-manageable-org.js'
import { rightsOf } from '../../../services/authorization-model.service.js'
import { redisRbacRepository } from '../../../services/redis-rbac.repository.js'

function request(organizationId: string): FastifyRequest {
  return {
    userContext: { id: 'subject-olivia', email: 'olivia@acme.test' },
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
    state.held = { groups: [], roles: [], permissions: [] }
    state.rosters = {}
    state.memberOf = []
    state.directoryRoles = {}
    state.env.ORGANISATION_SOURCE = 'directory'
  })

  it('admits a roster admin who is a member, with no group granting in the org', async () => {
    state.rosters[ACME] = ['olivia@acme.test']
    state.memberOf = [ACME]

    const { req, rep } = await chain(ACME)

    expect(rep.code).toBeUndefined()
    expect(req.rbacInfo?.permissions).toContain('org:manage_users')
  })

  it('admits the directory org_admin role the same way', async () => {
    state.directoryRoles[ACME] = [{ subjectId: 'subject-olivia', role: 'org_admin' }]
    state.memberOf = [ACME]

    const { rep } = await chain(ACME)

    expect(rep.code).toBeUndefined()
  })

  it('refuses the roster admin of Acme on Globex, even as a Globex member', async () => {
    state.rosters[ACME] = ['olivia@acme.test']
    state.memberOf = [ACME, GLOBEX]

    const { rep } = await chain(GLOBEX)

    expect(rep.code).toBe(403)
  })

  it('refuses a roster entry without membership — the roster alone is not enough', async () => {
    state.rosters[ACME] = ['olivia@acme.test']
    state.memberOf = []

    const { rep } = await chain(ACME)

    expect(rep.code).toBe(403)
  })

  it('grants member management only — never a wildcard, never group assignment', async () => {
    state.rosters[ACME] = ['olivia@acme.test']
    state.memberOf = [ACME]

    const { req } = await chain(ACME)

    expect(req.rbacInfo?.permissions).not.toContain('*')
    const rep = reply()
    await requireServicePermission('users:assign_group')(req, rep as unknown as FastifyReply)
    expect(rep.code).toBe(403)
  })

  it('keeps what groups give alongside the org-admin rights', async () => {
    state.rosters[ACME] = ['olivia@acme.test']
    state.memberOf = [ACME]
    state.held = { groups: ['viewers'], roles: ['viewer'], permissions: ['clusters:read'] }

    const { req } = await chain(ACME)

    expect(req.rbacInfo?.permissions).toEqual(
      expect.arrayContaining(['clusters:read', 'org:manage_users']),
    )
  })

  it('still admits a roster admin when the group model cannot be read', async () => {
    state.rosters[ACME] = ['olivia@acme.test']
    state.memberOf = [ACME]
    vi.mocked(rightsOf).mockRejectedValueOnce(new Error('not in a cluster'))

    const { rep } = await chain(ACME)

    expect(rep.code).toBeUndefined()
  })

  it('answers 503, not 403, when neither the roster nor the model can be read', async () => {
    vi.mocked(redisRbacRepository.getOrgAdmins).mockRejectedValueOnce(new Error('redis down'))

    const { rep } = await chain(ACME)

    expect(rep.code).toBe(503)
  })

  it('is opt-in: a gate built without it never consults the roster', async () => {
    state.rosters[ACME] = ['olivia@acme.test']
    state.memberOf = [ACME]
    const req = request(ACME)
    const rep = reply()

    await requireServiceAdmin()(req, rep as unknown as FastifyReply)

    expect(rep.code).toBe(403)
    expect(redisRbacRepository.getOrgAdmins).not.toHaveBeenCalled()
  })
})
