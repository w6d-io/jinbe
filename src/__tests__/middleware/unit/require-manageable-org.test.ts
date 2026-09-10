import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import type { UserRbacInfo } from '../../../services/opa.service.js'

vi.mock('../../../services/organisation-store.js', () => ({
  organisationsForSubject: vi.fn().mockResolvedValue([]),
}))

vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: {
    emit: vi.fn().mockResolvedValue(undefined),
  },
}))

import { requireManageableOrg } from '../../../middleware/require-manageable-org.js'
import { organisationsForSubject } from '../../../services/organisation-store.js'
import { auditEventService } from '../../../services/audit-event.service.js'

function createMockRequest(
  email?: string,
  params?: Record<string, string>,
  rbacInfo?: UserRbacInfo
): FastifyRequest {
  return {
    // The directory is keyed on the identity, so a context without one can answer nothing —
    // exactly as a real session, which always carries the Kratos identityId.
    userContext: email ? { email, id: `subject-of-${email}` } : undefined,
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
    vi.mocked(organisationsForSubject).mockResolvedValue([])
  })

  it('returns 500 when rbacInfo is missing (requireServiceAdmin not run first)', async () => {
    const request = createMockRequest('actor@example.com', { organizationId: 'org-1' })
    const reply = createMockReply()

    await requireManageableOrg()(request, reply)

    expect(reply._statusCode).toBe(500)
    expect(organisationsForSubject).not.toHaveBeenCalled()
  })

  it('grants a wildcard * caller unrestricted reach without consulting OPA (legacy)', async () => {
    const request = createMockRequest('super@example.com', { organizationId: 'org-1' }, RBAC(['*']))
    const reply = createMockReply()

    await requireManageableOrg()(request, reply)

    expect(reply.send).not.toHaveBeenCalled()
    expect(organisationsForSubject).not.toHaveBeenCalled()
  })

  it('grants a non-wildcard caller when the org is in their manageable set', async () => {
    vi.mocked(organisationsForSubject).mockResolvedValue(['org-1', 'org-2'])
    const request = createMockRequest(
      'orgadmin@example.com',
      { organizationId: 'org-1' },
      RBAC(['org:manage_users', 'users:read'])
    )
    const reply = createMockReply()

    await requireManageableOrg()(request, reply)

    expect(reply.send).not.toHaveBeenCalled()
    expect(organisationsForSubject).toHaveBeenCalled()
  })

  it('returns 403 when the org is not in the manageable set (tenant isolation)', async () => {
    vi.mocked(organisationsForSubject).mockResolvedValue(['org-2'])
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
    vi.mocked(organisationsForSubject).mockResolvedValue([])
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
    expect(organisationsForSubject).not.toHaveBeenCalled()
  })

  it('respects a custom paramName', async () => {
    vi.mocked(organisationsForSubject).mockResolvedValue(['svc-7'])
    const request = createMockRequest('orgadmin@example.com', { customId: 'svc-7' }, RBAC(['org:manage_users']))
    const reply = createMockReply()

    await requireManageableOrg('customId')(request, reply)

    expect(reply.send).not.toHaveBeenCalled()
  })
})
