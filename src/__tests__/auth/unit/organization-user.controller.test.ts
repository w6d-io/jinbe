import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// Redis mutex is infrastructure — passthrough so these units need no Redis.
// The store the engine actually reads. Group changes land here, so a test that left it real
// would reach for Postgres.
// The model the gates read. See the helper for why they read a model rather than predicates.
vi.mock('../../../services/group-catalogue.js', async () =>
  (await import('../../helpers/group-catalogue-mock.js')).groupCatalogueMock())

vi.mock('../../../services/organisation-store.js', () => ({
  addToGroup: vi.fn().mockResolvedValue(undefined),
  applyGroupChange: vi.fn().mockResolvedValue(undefined),
  removeFromGroup: vi.fn().mockResolvedValue(undefined),
  groupsForSubjects: vi.fn().mockResolvedValue(new Map()),
  organisationStoreConfigured: vi.fn().mockReturnValue(true),
  organisationStoreMode: () => 'postgres',
  membershipRowsKept: () => true,
  OrganisationStoreUnavailableError: class OrganisationStoreUnavailableError extends Error {},
  // Membership is any organisation the person belongs to, not only the primary one.
  organisationsForSubject: vi.fn().mockResolvedValue([]),
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

import { organizationUserController } from '../../../controllers/organization-user.controller.js'
import { kratosService, KratosApiError } from '../../../services/kratos.service.js'
import { rbacService } from '../../../services/rbac.service.js'

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
// Suppress unused-import warning for KratosApiError (used via mock class)
void KratosApiError
