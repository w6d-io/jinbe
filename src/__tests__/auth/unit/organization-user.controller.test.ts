import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// Redis mutex is infrastructure — passthrough so these units need no Redis.
vi.mock('../../../services/redis-lock.js', () => ({
  withRedisLock: (_name: string, fn: () => unknown) => fn(),
}))

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getIdentity: vi.fn(),
    getUserGroups: vi.fn(),
    updateUserGroups: vi.fn(),
    findByEmail: vi.fn(),
  },
  KratosApiError: class KratosApiError extends Error {
    statusCode: number
    constructor(statusCode: number, message: string) {
      super(message)
      this.statusCode = statusCode
      this.name = 'KratosApiError'
    }
  },
}))

vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: {
    getAvailableGroups: vi.fn(),
    validateGroups: vi.fn(),
    notifyBindingsChanged: vi.fn().mockResolvedValue(undefined),
    isAdminPowerGroup: vi.fn().mockResolvedValue(false),
    // Default false: the admin-power groups in these cases are org-scoped, not
    // global, so the wildcard_in_org gate is exercised as before.
    groupGrantsGlobalPower: vi.fn().mockResolvedValue(false),
    // Base group `users` is empty → exempt from the delegation gate.
    isEmptyGroup: vi.fn().mockResolvedValue(true),
    findPrivilegedGroupRequiringMFA: vi.fn().mockResolvedValue(null),
  },
}))

vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: {
    emit: vi.fn().mockResolvedValue(undefined),
  },
}))

vi.mock('../../../services/opa.service.js', () => ({
  opaService: {
    // org-scoped delegation decision; default deny (fail-closed). Admin-power
    // cases set it explicitly to model an OPA allow/deny.
    canGrant: vi.fn().mockResolvedValue(false),
  },
}))

import { organizationUserController } from '../../../controllers/organization-user.controller.js'
import { kratosService, KratosApiError } from '../../../services/kratos.service.js'
import { rbacService } from '../../../services/rbac.service.js'
import { opaService } from '../../../services/opa.service.js'

const ORG = '11111111-1111-1111-1111-111111111111'
const OTHER_ORG = '22222222-2222-2222-2222-222222222222'
const USER_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

function createReply() {
  const reply = {
    _statusCode: undefined as number | undefined,
    _body: undefined as unknown,
    status: vi.fn().mockImplementation(function (this: typeof reply, code: number) {
      this._statusCode = code
      return this
    }),
    send: vi.fn().mockImplementation(function (this: typeof reply, body?: unknown) {
      this._body = body
      return this
    }),
  }
  return reply as unknown as FastifyReply & { _statusCode?: number; _body?: unknown }
}

function makeIdentity(orgId: string, email = 'user@example.com') {
  return {
    id: USER_ID,
    schema_id: 'default',
    state: 'active',
    traits: { email },
    organization_id: orgId,
  }
}

describe('OrganizationUserController.getUserGroups', () => {
  beforeEach(() => vi.clearAllMocks())

  it('returns email + groups + availableGroups for in-org user', async () => {
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(ORG) as never)
    vi.mocked(kratosService.getUserGroups).mockResolvedValue(['users'])
    vi.mocked(rbacService.getAvailableGroups).mockResolvedValue(['users', 'admins'])

    const request = {
      params: { organizationId: ORG, id: USER_ID },
    } as unknown as FastifyRequest
    const reply = createReply()

    await organizationUserController.getUserGroups(request as never, reply)

    expect(reply.send).toHaveBeenCalledWith({
      email: 'user@example.com',
      groups: ['users'],
      availableGroups: ['users', 'admins'],
    })
  })

  it('throws KratosApiError 404 when identity belongs to a different organization', async () => {
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(OTHER_ORG) as never)

    const request = {
      params: { organizationId: ORG, id: USER_ID },
    } as unknown as FastifyRequest
    const reply = createReply()

    await expect(
      organizationUserController.getUserGroups(request as never, reply)
    ).rejects.toMatchObject({
      statusCode: 404,
      message: 'User not found in this organization',
    })
  })
})

describe('OrganizationUserController.updateUserGroups', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue(null)
    vi.mocked(kratosService.getUserGroups).mockResolvedValue([])
    vi.mocked(opaService.canGrant).mockResolvedValue(false)
  })

  it('rejects when target identity is in a different org (404)', async () => {
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(OTHER_ORG) as never)
    vi.mocked(rbacService.validateGroups).mockResolvedValue(undefined as never)

    const request = {
      params: { organizationId: ORG, id: USER_ID },
      body: { groups: ['users'] },
      ip: '127.0.0.1',
      userContext: { email: 'actor@example.com', aal: 'aal2', authenticatedAt: new Date() },
      rbacInfo: { email: 'actor@example.com', groups: [], roles: [], permissions: ['*'] },
    } as unknown as FastifyRequest

    const reply = createReply()

    await expect(
      organizationUserController.updateUserGroups(request as never, reply)
    ).rejects.toMatchObject({ statusCode: 404 })
  })

  it('blocks privilege escalation (422) when OPA denies delegation of an admin-power group', async () => {
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(ORG) as never)
    vi.mocked(rbacService.validateGroups).mockResolvedValue(undefined as never)
    vi.mocked(rbacService.isAdminPowerGroup).mockImplementation(async (g: string) => g === 'admins')
    // OPA delegation policy refuses (default beforeEach deny); the guard blocks.

    const request = {
      params: { organizationId: ORG, id: USER_ID },
      body: { groups: ['admins'] },
      ip: '127.0.0.1',
      userContext: { email: 'actor@example.com', aal: 'aal2', authenticatedAt: new Date() },
      rbacInfo: {
        email: 'actor@example.com',
        groups: ['admins'],
        roles: ['admin'],
        permissions: ['rbac:write'],
      },
    } as unknown as FastifyRequest

    const reply = createReply()

    await organizationUserController.updateUserGroups(request as never, reply)

    expect(reply._statusCode).toBe(422)
    expect(reply._body).toMatchObject({
      error: 'privilege_escalation_blocked',
      blockingGroup: 'admins',
    })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('allows OPA-permitted delegation by a non-wildcard org admin (MFA gate still applies)', async () => {
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(ORG) as never)
    vi.mocked(rbacService.validateGroups).mockResolvedValue(undefined as never)
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(true)
    // Non-wildcard org admin → the decision is the OPA delegation policy, which
    // allows the grant (containment holds); the MFA gate is downstream and still
    // blocks until the target enrols a second factor.
    vi.mocked(opaService.canGrant).mockResolvedValue(true)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue('admins')

    const request = {
      params: { organizationId: ORG, id: USER_ID },
      body: { groups: ['admins'] },
      ip: '127.0.0.1',
      userContext: { email: 'orgadmin@example.com', aal: 'aal2', authenticatedAt: new Date() },
      rbacInfo: {
        email: 'orgadmin@example.com',
        groups: ['org-admins'],
        roles: ['organization_admin'],
        permissions: ['org:manage_users', 'users:read'],
      },
    } as unknown as FastifyRequest

    const reply = createReply()

    await organizationUserController.updateUserGroups(request as never, reply)

    expect(opaService.canGrant).toHaveBeenCalled()
    expect(reply._statusCode).toBe(422)
    expect(reply._body).toMatchObject({
      error: 'mfa_required',
      targetEmail: 'user@example.com',
    })
  })

  it('routes a wildcard (*) caller through can_grant on the org endpoint (rego is authoritative)', async () => {
    // No client-side bypass: even a `*` caller is subject to OPA can_grant. The
    // rego decides (its service-admin tier), so a single-service grant it allows
    // succeeds and canGrant IS consulted.
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(ORG) as never)
    vi.mocked(rbacService.validateGroups).mockResolvedValue(undefined as never)
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue(null)
    vi.mocked(opaService.canGrant).mockResolvedValue(true)
    vi.mocked(kratosService.updateUserGroups).mockResolvedValue(undefined as never)

    const request = {
      params: { organizationId: ORG, id: USER_ID },
      body: { groups: ['kuma-viewers'] },
      ip: '127.0.0.1',
      userContext: { email: 'super@example.com', aal: 'aal2', authenticatedAt: new Date() },
      rbacInfo: {
        email: 'super@example.com',
        groups: ['super_admins'],
        roles: ['super_admin'],
        permissions: ['*'],
      },
    } as unknown as FastifyRequest

    const reply = createReply()

    await organizationUserController.updateUserGroups(request as never, reply)

    expect(opaService.canGrant).toHaveBeenCalledWith({
      actor: { email: 'super@example.com' },
      target_group: 'kuma-viewers',
      target_org: ORG,
    })
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('user@example.com', ['kuma-viewers'])
  })

  it('happy path: returns id + organizationId + updatedAt and persists groups', async () => {
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(ORG) as never)
    vi.mocked(rbacService.validateGroups).mockResolvedValue(undefined as never)
    vi.mocked(kratosService.updateUserGroups).mockResolvedValue(undefined as never)

    const request = {
      params: { organizationId: ORG, id: USER_ID },
      body: { groups: ['users'] },
      ip: '127.0.0.1',
      userContext: { email: 'actor@example.com', aal: 'aal2', authenticatedAt: new Date() },
      rbacInfo: {
        email: 'actor@example.com',
        groups: ['admins'],
        roles: ['admin'],
        permissions: ['rbac:write'],
      },
    } as unknown as FastifyRequest

    const reply = createReply()

    await organizationUserController.updateUserGroups(request as never, reply)

    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('user@example.com', ['users'])
    expect(reply.send).toHaveBeenCalled()
    const body = reply._body as Record<string, unknown>
    expect(body).toMatchObject({
      id: USER_ID,
      organizationId: ORG,
      email: 'user@example.com',
      groups: ['users'],
    })
    expect(typeof body.updatedAt).toBe('string')
  })

  it('defaults to ["users"] when body groups is empty', async () => {
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(ORG) as never)
    vi.mocked(rbacService.validateGroups).mockResolvedValue(undefined as never)
    vi.mocked(kratosService.updateUserGroups).mockResolvedValue(undefined as never)

    const request = {
      params: { organizationId: ORG, id: USER_ID },
      body: { groups: [] },
      ip: '127.0.0.1',
      userContext: { email: 'actor@example.com', aal: 'aal2', authenticatedAt: new Date() },
      rbacInfo: {
        email: 'actor@example.com',
        groups: ['admins'],
        roles: ['admin'],
        permissions: ['rbac:write'],
      },
    } as unknown as FastifyRequest

    const reply = createReply()

    await organizationUserController.updateUserGroups(request as never, reply)

    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('user@example.com', ['users'])
  })
})

// Suppress unused-import warning for KratosApiError (used via mock class)
void KratosApiError
