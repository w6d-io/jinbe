import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

vi.mock('../../../services/opa.service.js', () => ({
  opaService: {
    assignableGroups: vi.fn().mockResolvedValue([]),
    // Default: not a service-`*` actor → the delegated (membership) path is used.
    getUserInfo: vi.fn().mockResolvedValue(null),
  },
}))

vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getServiceForOrg: vi.fn().mockResolvedValue(null),
    getGroups: vi.fn().mockResolvedValue({}),
  },
}))

// The controller pulls in these services at import time; stub the surface it
// touches so the module loads without real Redis/Kratos/OPAL.
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {},
  KratosApiError: class extends Error {},
}))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: {} }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn() } }))
vi.mock('../../../services/user-groups.service.js', () => ({ userGroupsService: {} }))
vi.mock('../../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { organizationUserController } from '../../../controllers/organization-user.controller.js'
import { opaService } from '../../../services/opa.service.js'
import { redisRbacRepository } from '../../../services/redis-rbac.repository.js'

// Real catalog shape (multi-service `viewers`/`admins`, single-service seeds).
const GROUPS = {
  admins: { jinbe: ['admin'], kuma: ['admin'], payments: ['admin'] },
  viewers: { jinbe: ['viewer'], kuma: ['viewer'], payments: ['viewer'] },
  'kuma-viewers': { kuma: ['viewer'] },
  'kuma-org-admins': { kuma: ['org_admin'] },
  'jinbe-viewers': { jinbe: ['viewer'] },
  super_admins: { global: ['super_admin'] },
  // Carries an EMPTY global key alongside a single service. can_grant denies it
  // (its grant_target_service requires every key == the org service), so the
  // feed must exclude it too — even for a Tier B service-* actor. (F3)
  'kuma-with-empty-global': { global: [], kuma: ['viewer'] },
  users: {},
}

function createReply(): FastifyReply & { _statusCode?: number; _body?: unknown } {
  const reply = {
    _statusCode: undefined as number | undefined,
    _body: undefined as unknown,
    status: vi.fn().mockImplementation(function (this: typeof reply, c: number) { this._statusCode = c; return this }),
    send: vi.fn().mockImplementation(function (this: typeof reply, b: unknown) { this._body = b; return this }),
  }
  return reply as unknown as FastifyReply & { _statusCode?: number; _body?: unknown }
}

function req(email: string | undefined, organizationId = 'org-kuma') {
  return {
    params: { organizationId },
    userContext: email ? { email } : undefined,
  } as unknown as FastifyRequest<{ Params: { organizationId: string } }>
}

describe('OrganizationUserController.listAssignableGroups', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(redisRbacRepository.getGroups).mockResolvedValue(GROUPS as never)
    vi.mocked(opaService.getUserInfo).mockResolvedValue(null)
  })

  it('returns only single-service groups bound to the org service, excluding multi-service/other-service/global', async () => {
    vi.mocked(redisRbacRepository.getServiceForOrg).mockResolvedValue('kuma')
    vi.mocked(opaService.assignableGroups).mockResolvedValue([
      'kuma-viewers', 'kuma-org-admins', 'jinbe-viewers', 'viewers', 'super_admins',
    ])

    const reply = createReply()
    await organizationUserController.listAssignableGroups(req('orgadmin@example.com'), reply)

    expect(opaService.assignableGroups).toHaveBeenCalledWith('orgadmin@example.com')
    expect(reply._body).toEqual({ groups: ['kuma-viewers', 'kuma-org-admins'] })
  })

  it('returns [] when the org has no service mapping (fail-safe)', async () => {
    vi.mocked(redisRbacRepository.getServiceForOrg).mockResolvedValue(null)
    vi.mocked(opaService.assignableGroups).mockResolvedValue(['kuma-viewers'])

    const reply = createReply()
    await organizationUserController.listAssignableGroups(req('orgadmin@example.com'), reply)

    expect(reply._body).toEqual({ groups: [] })
  })

  it('returns [] when OPA yields no assignable groups (fail-closed)', async () => {
    vi.mocked(redisRbacRepository.getServiceForOrg).mockResolvedValue('kuma')
    vi.mocked(opaService.assignableGroups).mockResolvedValue([])

    const reply = createReply()
    await organizationUserController.listAssignableGroups(req('orgadmin@example.com'), reply)

    expect(reply._body).toEqual({ groups: [] })
  })

  it('returns 401 when the caller has no email', async () => {
    const reply = createReply()
    await organizationUserController.listAssignableGroups(req(undefined), reply)

    expect(reply._statusCode).toBe(401)
    expect(opaService.assignableGroups).not.toHaveBeenCalled()
  })

  // ── Service-`*` actor (super_admin) — mirrors can_grant Tier B ────────────

  it('offers a service-* actor ALL single-service groups for the org service, even when assignable_groups is empty', async () => {
    // A super_admin is not an org member, so the membership-based delegated set
    // is empty — but can_grant Tier B admits them for any non-global single-
    // service group in the service. The feed must mirror that (else the picker
    // is empty for super_admins, the "0 assignable groups" symptom).
    vi.mocked(redisRbacRepository.getServiceForOrg).mockResolvedValue('kuma')
    vi.mocked(opaService.assignableGroups).mockResolvedValue([])
    vi.mocked(opaService.getUserInfo).mockResolvedValue({
      email: 'super@example.com', groups: ['super_admins'], roles: ['super_admin'], permissions: ['*'],
    })

    const reply = createReply()
    await organizationUserController.listAssignableGroups(req('super@example.com'), reply)

    expect(reply._body).toEqual({ groups: ['kuma-viewers', 'kuma-org-admins'] })
    // F3: a group with an (even empty) global key is NOT offered — can_grant denies it.
    expect((reply._body as { groups: string[] }).groups).not.toContain('kuma-with-empty-global')
    // Tier B does not consult the membership-based delegated set.
    expect(opaService.assignableGroups).not.toHaveBeenCalled()
  })

  it('never offers global or multi-service groups to a service-* actor (defense-in-depth)', async () => {
    vi.mocked(redisRbacRepository.getServiceForOrg).mockResolvedValue('jinbe')
    vi.mocked(opaService.getUserInfo).mockResolvedValue({
      email: 'super@example.com', groups: ['super_admins'], roles: [], permissions: ['*'],
    })

    const reply = createReply()
    await organizationUserController.listAssignableGroups(req('super@example.com', 'org-jinbe'), reply)

    // Only jinbe single-service groups; multi-service (`admins`/`viewers`) and
    // global (`super_admins`) are excluded even for a wildcard actor.
    expect(reply._body).toEqual({ groups: ['jinbe-viewers'] })
  })
})
