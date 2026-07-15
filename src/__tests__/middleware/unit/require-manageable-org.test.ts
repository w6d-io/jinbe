import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import type { UserRbacInfo } from '../../../services/opa.service.js'

vi.mock('../../../services/opa.service.js', () => ({
  opaService: {
    manageableOrgs: vi.fn().mockResolvedValue([]),
  },
}))

vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: {
    emit: vi.fn().mockResolvedValue(undefined),
  },
}))

import { requireManageableOrg } from '../../../middleware/require-manageable-org.js'
import { opaService } from '../../../services/opa.service.js'
import { auditEventService } from '../../../services/audit-event.service.js'

function createMockRequest(
  email?: string,
  params?: Record<string, string>,
  rbacInfo?: UserRbacInfo
): FastifyRequest {
  return {
    userContext: email ? { email } : undefined,
    rbacInfo,
    method: 'GET',
    url: '/api/organizations/org-1/users',
    ip: '127.0.0.1',
    headers: { 'user-agent': 'test' },
    params: params ?? {},
    log: { warn: vi.fn(), debug: vi.fn(), info: vi.fn() },
  } as unknown as FastifyRequest
}

function createMockReply(): FastifyReply & { _statusCode?: number; _body?: unknown } {
  const reply = {
    _statusCode: undefined as number | undefined,
    _body: undefined as unknown,
    status: vi.fn().mockImplementation(function (this: typeof reply, code: number) {
      this._statusCode = code
      return this
    }),
    send: vi.fn().mockImplementation(function (this: typeof reply, body: unknown) {
      this._body = body
      return this
    }),
  }
  return reply as unknown as FastifyReply & { _statusCode?: number; _body?: unknown }
}

const RBAC = (permissions: string[]): UserRbacInfo => ({
  email: 'actor@example.com',
  groups: [],
  roles: [],
  permissions,
})

describe('requireManageableOrg middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(opaService.manageableOrgs).mockResolvedValue([])
  })

  it('returns 500 when rbacInfo is missing (requireServiceAdmin not run first)', async () => {
    const request = createMockRequest('actor@example.com', { organizationId: 'org-1' })
    const reply = createMockReply()

    await requireManageableOrg()(request, reply)

    expect(reply._statusCode).toBe(500)
    expect(opaService.manageableOrgs).not.toHaveBeenCalled()
  })

  it('grants a wildcard * caller unrestricted reach without consulting OPA (legacy)', async () => {
    const request = createMockRequest('super@example.com', { organizationId: 'org-1' }, RBAC(['*']))
    const reply = createMockReply()

    await requireManageableOrg()(request, reply)

    expect(reply.send).not.toHaveBeenCalled()
    expect(opaService.manageableOrgs).not.toHaveBeenCalled()
  })

  it('grants a non-wildcard caller when the org is in their manageable set', async () => {
    vi.mocked(opaService.manageableOrgs).mockResolvedValue(['org-1', 'org-2'])
    const request = createMockRequest(
      'orgadmin@example.com',
      { organizationId: 'org-1' },
      RBAC(['org:manage_users', 'users:read'])
    )
    const reply = createMockReply()

    await requireManageableOrg()(request, reply)

    expect(reply.send).not.toHaveBeenCalled()
    expect(opaService.manageableOrgs).toHaveBeenCalledWith('orgadmin@example.com')
  })

  it('returns 403 when the org is not in the manageable set (tenant isolation)', async () => {
    vi.mocked(opaService.manageableOrgs).mockResolvedValue(['org-2'])
    const request = createMockRequest(
      'orgadmin@example.com',
      { organizationId: 'org-1' },
      RBAC(['org:manage_users'])
    )
    const reply = createMockReply()

    await requireManageableOrg()(request, reply)

    expect(reply._statusCode).toBe(403)
    expect(reply._body).toMatchObject({ error: 'Forbidden' })
    expect(auditEventService.emit).toHaveBeenCalledWith(
      expect.objectContaining({ verb: 'deny', reason: 'not_org_admin' })
    )
  })

  it('fail-closed: 403 when manageableOrgs is empty (OPA error/unreachable)', async () => {
    vi.mocked(opaService.manageableOrgs).mockResolvedValue([])
    const request = createMockRequest(
      'orgadmin@example.com',
      { organizationId: 'org-1' },
      RBAC(['org:manage_users'])
    )
    const reply = createMockReply()

    await requireManageableOrg()(request, reply)

    expect(reply._statusCode).toBe(403)
  })

  it('returns 401 for a non-wildcard caller with no email', async () => {
    const request = createMockRequest(undefined, { organizationId: 'org-1' }, RBAC(['org:manage_users']))
    const reply = createMockReply()

    await requireManageableOrg()(request, reply)

    expect(reply._statusCode).toBe(401)
    expect(opaService.manageableOrgs).not.toHaveBeenCalled()
  })

  it('respects a custom paramName', async () => {
    vi.mocked(opaService.manageableOrgs).mockResolvedValue(['svc-7'])
    const request = createMockRequest('orgadmin@example.com', { customId: 'svc-7' }, RBAC(['org:manage_users']))
    const reply = createMockReply()

    await requireManageableOrg('customId')(request, reply)

    expect(reply.send).not.toHaveBeenCalled()
  })
})
