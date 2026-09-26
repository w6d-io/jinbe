import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// J-3 / story 7: managing an org's API keys needs THAT org — its roster admin, super_admin, or a
// member holding org:manage_api_keys there (site grants ∪ org_grants[that org]). Which of those holds
// is OPA's `rbac.decision` for the request, exactly as at the gateway (the rule itself is proven by
// opal-policies org_layer_test.rego); jinbe asks and obeys.
// J-1: the grant routes need that org's admin (`manageable_orgs`), or super_admin (`super_admin`).

const ACME = '11111111-1111-1111-1111-111111111111'
const GLOBEX = '22222222-2222-2222-2222-222222222222'
const X = 'x@acme.test'

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))

import { requireOrgAdmin, requireOrgPermission } from '../../../middleware/require-org-permission.js'
import { ORG_ADMIN_PERMISSIONS } from '../../../services/org-admin.js'
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
    log: { warn: vi.fn(), debug: vi.fn() },
  } as unknown as FastifyRequest
  const rep = {
    code: undefined as number | undefined,
    status(c: number) { this.code = c; return this },
    send() { return this },
  }
  return guard(req, rep as unknown as FastifyReply).then(() => rep.code)
}

const apiKeys = () => requireOrgPermission('org:manage_api_keys')

beforeEach(() => {
  vi.clearAllMocks()
  resetOpaWorld()
})

describe('requireOrgPermission("org:manage_api_keys") — API keys of THAT org', () => {
  it('org admins hold org:manage_api_keys', () => {
    expect(ORG_ADMIN_PERMISSIONS).toContain('org:manage_api_keys')
  })

  it('is marked with the permission it enforces (published route table)', () => {
    expect(enforcedBy(apiKeys())).toBe('org:manage_api_keys')
  })

  it('401 without an identity, before asking OPA', async () => {
    expect(await run(apiKeys(), ACME, {})).toBe(401)
    expect(decide).not.toHaveBeenCalled()
  })

  it('asks rbac.decision about this very request', async () => {
    opaWorld.decide = () => true
    expect(await run(apiKeys(), ACME)).toBeUndefined()
    expect(decide).toHaveBeenCalledWith({
      email: X,
      method: 'GET',
      path: `/api/organizations/${ACME}/api-keys`,
      aal: 'aal2',
      client: false,
    })
  })

  it('lets in whoever OPA admits there (roster admin, super_admin, member holding it)', async () => {
    opaWorld.manageable[X] = [ACME]
    expect(await run(apiKeys(), ACME)).toBeUndefined()
    resetOpaWorld()
    opaWorld.superAdmins.add(X)
    expect(await run(apiKeys(), GLOBEX)).toBeUndefined()
  })

  it('refuses (403, audited) whoever OPA refuses — e.g. the admin of ANOTHER org', async () => {
    opaWorld.manageable[X] = [GLOBEX]
    expect(await run(apiKeys(), ACME)).toBe(403)
    expect(auditEventService.emit).toHaveBeenCalledWith(
      expect.objectContaining({ verb: 'deny', reason: 'missing_permission:org:manage_api_keys' }),
    )
  })

  it('503, not 403, when OPA cannot be asked', async () => {
    opaWorld.down = true
    expect(await run(apiKeys(), ACME)).toBe(503)
  })
})

describe('requireOrgAdmin — grant routes', () => {
  it('lets the org admin of that org and super_admin in', async () => {
    opaWorld.manageable[X] = [ACME]
    expect(await run(requireOrgAdmin(), ACME)).toBeUndefined()
    resetOpaWorld()
    opaWorld.superAdmins.add(X)
    expect(await run(requireOrgAdmin(), ACME)).toBeUndefined()
  })

  it('refuses a member holding permissions there but not administering it', async () => {
    opaWorld.members[X] = [ACME]
    opaWorld.permissions[X] = ['org:manage_users', 'users:assign_group']
    expect(await run(requireOrgAdmin(), ACME)).toBe(403)
  })

  it('refuses the admin of another org', async () => {
    opaWorld.manageable[X] = [GLOBEX]
    expect(await run(requireOrgAdmin(), ACME)).toBe(403)
  })

  it('503 when it cannot tell', async () => {
    opaWorld.down = true
    expect(await run(requireOrgAdmin(), ACME)).toBe(503)
  })
})
