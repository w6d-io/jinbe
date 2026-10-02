import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// Creating somebody in an organisation: always the base `users` group, never a platform group; org
// roles given at creation clear the holding rule BEFORE anything is created.

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    createIdentity: vi.fn(),
    deleteIdentity: vi.fn().mockResolvedValue(undefined),
    sendRecoveryEmail: vi.fn().mockResolvedValue(undefined),
    invalidateGroupsCache: vi.fn(),
  },
  KratosApiError: class extends Error {},
}))
vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: { notifyBindingsChanged: vi.fn().mockResolvedValue(undefined) },
}))
vi.mock('../../../services/org-roles.repository.js', () => ({
  orgRolesRepository: { setForMember: vi.fn(async () => {}), forgetMember: vi.fn(async () => {}) },
}))
vi.mock('../../../services/org-role-grants.js', () => ({ orgRoleRefusals: vi.fn(async () => []) }))
vi.mock('../../../services/direct-grants.service.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../services/direct-grants.service.js')>()
  return { ...real, directGrantsService: { check: vi.fn(async () => {}), replace: vi.fn(async () => []) } }
})
vi.mock('../../../services/organisation-store.js', () => ({
  addMember: vi.fn(async () => {}),
  membershipRowsKept: () => true,
  OrganisationStoreUnavailableError: class extends Error {},
}))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn().mockResolvedValue(undefined) } }))
vi.mock('../../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { organizationUserController } from '../../../controllers/organization-user.controller.js'
import { kratosService } from '../../../services/kratos.service.js'
import { orgRolesRepository } from '../../../services/org-roles.repository.js'
import { orgRoleRefusals } from '../../../services/org-role-grants.js'
import { directGrantsService, GrantsRefusedError } from '../../../services/direct-grants.service.js'

const ORG = '11111111-1111-1111-1111-111111111111'

function createReply(): FastifyReply & { _statusCode?: number; _body?: unknown } {
  const reply = {
    _statusCode: undefined as number | undefined,
    _body: undefined as unknown,
    status: vi.fn().mockImplementation(function (this: typeof reply, c: number) { this._statusCode = c; return this }),
    send: vi.fn().mockImplementation(function (this: typeof reply, b: unknown) { this._body = b; return this }),
  }
  return reply as unknown as FastifyReply & { _statusCode?: number; _body?: unknown }
}

function req(body: Record<string, unknown>) {
  return {
    params: { organizationId: ORG },
    body,
    ip: '127.0.0.1',
    userContext: { email: 'owner@example.com', aal: 'aal2', authenticatedAt: new Date() },
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  } as unknown as FastifyRequest<{ Params: { organizationId: string }; Body: never }>
}

const CREATED = {
  id: 'new-user-1',
  state: 'active',
  traits: { email: 'new@example.com' },
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

describe('OrganizationUserController.createUser — org roles', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(kratosService.createIdentity).mockResolvedValue(CREATED as never)
  })

  it('creates with no platform group and no org role when none is asked', async () => {
    const reply = createReply()
    await organizationUserController.createUser(req({ email: 'new@example.com' }) as never, reply)

    expect(kratosService.createIdentity).toHaveBeenCalledWith(expect.objectContaining({ metadata_admin: { groups: [] } }))
    expect(orgRolesRepository.setForMember).not.toHaveBeenCalled()
    expect(reply._statusCode).toBe(201)
  })

  it('assigns the org roles asked, once each, after the identity exists', async () => {
    const reply = createReply()
    await organizationUserController.createUser(req({ email: 'new@example.com', roles: ['jinbe:viewer', 'jinbe:viewer', 'payroll:clerk'] }) as never, reply)

    expect(orgRoleRefusals).toHaveBeenCalledWith('owner@example.com', ORG, ['jinbe:viewer', 'payroll:clerk'], { email: 'new@example.com', joining: true })
    expect(orgRolesRepository.setForMember).toHaveBeenCalledWith(ORG, 'new-user-1', ['jinbe:viewer', 'payroll:clerk'])
    expect(reply._statusCode).toBe(201)
  })

  it('refuses a role beyond what the caller holds before creating anybody', async () => {
    vi.mocked(orgRoleRefusals).mockResolvedValueOnce([{ role: 'jinbe:owner', reason: 'grant_exceeds_own' }] as never)
    const reply = createReply()
    await organizationUserController.createUser(req({ email: 'new@example.com', roles: ['jinbe:owner'] }) as never, reply)

    expect(reply._statusCode).toBe(403)
    expect(reply._body).toMatchObject({ refused: [{ role: 'jinbe:owner', reason: 'grant_exceeds_own' }] })
    expect(kratosService.createIdentity).not.toHaveBeenCalled()
    expect(orgRolesRepository.setForMember).not.toHaveBeenCalled()
  })

  it('takes no platform group from the body', async () => {
    const reply = createReply()
    await organizationUserController.createUser(req({ email: 'new@example.com', groups: ['super_admins'] }) as never, reply)

    expect(kratosService.createIdentity).toHaveBeenCalledWith(expect.objectContaining({ metadata_admin: { groups: [] } }))
  })

  it('direct grants in this org, checked before anybody is created (the new member joining), written after', async () => {
    const grant = { scope: ORG, app: 'jinbe', kind: 'role' as const, name: 'viewer' }
    const reply = createReply()
    await organizationUserController.createUser(req({ email: 'new@example.com', grants: [grant] }) as never, reply)
    expect(directGrantsService.check).toHaveBeenCalledWith(expect.objectContaining({ subjectId: '', granteeEmail: 'new@example.com', wanted: [grant], joining: true }))
    expect(directGrantsService.replace).toHaveBeenCalledWith(expect.objectContaining({ subjectId: 'new-user-1', joining: true }))
    expect(reply._statusCode).toBe(201)
  })

  it('a refused grant: 403 with what was refused, nobody created', async () => {
    vi.mocked(directGrantsService.check).mockRejectedValueOnce(new GrantsRefusedError([{ grant: { scope: ORG, app: 'jinbe', kind: 'role', name: 'owner' }, reasons: ['missing_permissions'], missing: ['org.keys:write'], grantedBy: ['jinbe:owner'] }]))
    const reply = createReply()
    await organizationUserController.createUser(req({ email: 'new@example.com', grants: [{ scope: ORG, app: 'jinbe', kind: 'role', name: 'owner' }] }) as never, reply)
    expect(reply._statusCode).toBe(403)
    expect(reply._body).toMatchObject({ code: 'grant_exceeds_own', refused: [{ grant: { name: 'owner' } }] })
    expect(kratosService.createIdentity).not.toHaveBeenCalled()
  })
})
