import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

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
  rbacService: {
    validateGroups: vi.fn().mockResolvedValue(undefined),
    notifyBindingsChanged: vi.fn().mockResolvedValue(undefined),
  },
}))

vi.mock('../../../services/user-groups.service.js', () => ({
  userGroupsService: { applyGroupUpdate: vi.fn() },
}))

vi.mock('../../../services/opa.service.js', () => ({ opaService: {} }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: {} }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn().mockResolvedValue(undefined) } }))
vi.mock('../../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { organizationUserController } from '../../../controllers/organization-user.controller.js'
import { kratosService } from '../../../services/kratos.service.js'
import { rbacService } from '../../../services/rbac.service.js'
import { userGroupsService } from '../../../services/user-groups.service.js'

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

function req(body: Record<string, unknown>, permissions: string[] = ['org:manage_users']) {
  return {
    params: { organizationId: ORG },
    body,
    ip: '127.0.0.1',
    userContext: { email: 'orgadmin@example.com', aal: 'aal2', authenticatedAt: new Date() },
    rbacInfo: { email: 'orgadmin@example.com', groups: [], roles: [], permissions },
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

describe('OrganizationUserController.createUser — group assignment', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(kratosService.createIdentity).mockResolvedValue(CREATED as never)
  })

  it('creates with base users (no delegation check) when groups omitted', async () => {
    const reply = createReply()
    await organizationUserController.createUser(req({ email: 'new@example.com' }) as never, reply)

    // The base `users` group is PERSISTED on the identity up front, so an
    // invited user visibly holds `users` (not null) without a separate write.
    expect(kratosService.createIdentity).toHaveBeenCalledWith(
      expect.objectContaining({ metadata_admin: { groups: ['users'] } })
    )
    expect(userGroupsService.applyGroupUpdate).not.toHaveBeenCalled()
    expect(rbacService.validateGroups).not.toHaveBeenCalled()
    expect(reply._statusCode).toBe(201)
  })

  it('treats an explicit ["users"] as the base group (no delegation check)', async () => {
    const reply = createReply()
    await organizationUserController.createUser(
      req({ email: 'new@example.com', groups: ['users'] }) as never,
      reply
    )

    expect(userGroupsService.applyGroupUpdate).not.toHaveBeenCalled()
    expect(reply._statusCode).toBe(201)
  })

  it('validates BEFORE create and does not create when the group is invalid', async () => {
    vi.mocked(rbacService.validateGroups).mockRejectedValueOnce(
      Object.assign(new Error('unknown group'), { statusCode: 400 })
    )
    const reply = createReply()

    await expect(
      organizationUserController.createUser(
        req({ email: 'new@example.com', groups: ['ghost'] }) as never,
        reply
      )
    ).rejects.toBeTruthy()

    expect(kratosService.createIdentity).not.toHaveBeenCalled()
  })

  it('assigns a contained group through the guard and returns 201', async () => {
    vi.mocked(userGroupsService.applyGroupUpdate).mockResolvedValue({ ok: true, response: {} } as never)
    const reply = createReply()

    await organizationUserController.createUser(
      req({ email: 'new@example.com', groups: ['kuma-viewers'] }) as never,
      reply
    )

    expect(userGroupsService.applyGroupUpdate).toHaveBeenCalledWith(
      expect.objectContaining({
        newGroups: ['kuma-viewers'],
        privilegePolicy: { kind: 'wildcard_in_org', orgId: ORG },
      })
    )
    expect(kratosService.deleteIdentity).not.toHaveBeenCalled()
    expect(reply._statusCode).toBe(201)
  })

  it('rolls back the created identity when the grant is blocked', async () => {
    vi.mocked(userGroupsService.applyGroupUpdate).mockResolvedValue({
      ok: false,
      status: 422,
      body: { error: 'privilege_escalation_blocked' },
    } as never)
    const reply = createReply()

    await organizationUserController.createUser(
      req({ email: 'new@example.com', groups: ['admins'] }) as never,
      reply
    )

    expect(kratosService.deleteIdentity).toHaveBeenCalledWith('new-user-1')
    expect(reply._statusCode).toBe(422)
    expect(reply._body).toMatchObject({ error: 'privilege_escalation_blocked' })
  })

  it('routes a wildcard caller through the same guard (no client-derived policy flag)', async () => {
    // A `*` caller carries no special policy flag — authority is decided by OPA
    // can_grant (the rego), not by anything the controller passes.
    vi.mocked(userGroupsService.applyGroupUpdate).mockResolvedValue({ ok: true, response: {} } as never)
    const reply = createReply()

    await organizationUserController.createUser(
      req({ email: 'new@example.com', groups: ['kuma-viewers'] }, ['*']) as never,
      reply
    )

    expect(userGroupsService.applyGroupUpdate).toHaveBeenCalledWith(
      expect.objectContaining({
        privilegePolicy: { kind: 'wildcard_in_org', orgId: ORG },
        actor: expect.objectContaining({ email: 'orgadmin@example.com', ip: '127.0.0.1', aal: 'aal2' }),
      })
    )
  })
})
