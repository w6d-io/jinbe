import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// Redis mutex is infrastructure — passthrough so these units need no Redis.
// The store the engine actually reads. Group changes land here, so a test that left it real
// would reach for Postgres.
// The model the gates read. See the helper for why they read a model rather than predicates.
vi.mock('../../../services/authorization-model.service.js', async () =>
  (await import('../../helpers/authorization-model-mock.js')).authorizationModelMock())

vi.mock('../../../services/organisation-store.js', () => ({
  addToGroup: vi.fn().mockResolvedValue(undefined),
  removeFromGroup: vi.fn().mockResolvedValue(undefined),
  groupsForSubjects: vi.fn().mockResolvedValue(new Map()),
  organisationStoreConfigured: vi.fn().mockReturnValue(true),
}))

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
    notifyBindingsChanged: vi.fn().mockResolvedValue(undefined),
    // Default false: the admin-power groups in these cases are org-scoped, not
    // global, so the wildcard_in_org gate is exercised as before.
    // Base group `users` is empty → exempt from the delegation gate.
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

    const request = {
      params: { organizationId: ORG, id: USER_ID },
    } as unknown as FastifyRequest
    const reply = createReply()

    await organizationUserController.getUserGroups(request as never, reply)

    expect(reply.send).toHaveBeenCalledWith({
      email: 'user@example.com',
      groups: ['users'],
      availableGroups: [
        'admins',
        'devs',
        'kuma-viewers',
        'operators',
        'org_admins',
        'super_admins',
        'users',
        'viewers',
      ],
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
    vi.mocked(kratosService.getUserGroups).mockResolvedValue([])
    vi.mocked(opaService.canGrant).mockResolvedValue(false)
  })

  it('rejects when target identity is in a different org (404)', async () => {
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(OTHER_ORG) as never)

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

  it('refuses an org-scoped group change, because this model defines no delegation', async () => {
    // These three cases used to describe an OPA delegation policy deciding whether an org admin
    // could hand out a group inside their organisation. `strada.authz` has no such concept — no
    // permission expresses it — so the endpoint refuses and names the authority that is missing,
    // instead of asking an engine that stopped answering when the model changed.
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(ORG) as never)

    const request = {
      params: { organizationId: ORG, id: USER_ID },
      body: { groups: ['admins'] },
      ip: '127.0.0.1',
      userContext: { id: 'subject-actor', email: 'actor@example.com', aal: 'aal2', authenticatedAt: new Date() },
      rbacInfo: { email: 'actor@example.com', groups: [], roles: [], permissions: [] },
    } as unknown as FastifyRequest

    const reply = createReply()

    await organizationUserController.updateUserGroups(request as never, reply)

    expect(reply.status).toHaveBeenCalledWith(422)
    expect(reply._body).toMatchObject({ error: 'delegation_not_defined' })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('happy path: returns id + organizationId + updatedAt and persists groups', async () => {
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(ORG) as never)
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

    // The body asked for `users`, so `users` is written. The base group is only special in that
    // nothing forces it back any more.
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

  it('takes the last group away instead of putting the base one back', async () => {
    vi.mocked(kratosService.getIdentity).mockResolvedValue(makeIdentity(ORG) as never)
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

    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('user@example.com', [])
  })
})

// Suppress unused-import warning for KratosApiError (used via mock class)
void KratosApiError
