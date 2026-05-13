import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

const ORG_A = '11111111-1111-1111-1111-111111111111'
const ORG_B = '22222222-2222-2222-2222-222222222222'
const ORG_C = '33333333-3333-3333-3333-333333333333'

const { DEFAULT_IDENTITY } = vi.hoisted(() => ({
  DEFAULT_IDENTITY: {
    id: 'user-123',
    schema_id: 'default',
    state: 'active',
    traits: { email: 'user@example.org' },
    organization_id: null,
    metadata_admin: { organizations: [] },
    metadata_public: {},
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
}))

// ── Service mocks ────────────────────────────────────────────────────

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    findByEmail: vi.fn().mockResolvedValue(DEFAULT_IDENTITY),
    updateUserOrganizations: vi.fn().mockResolvedValue(DEFAULT_IDENTITY),
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
  },
}))

vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: {
    emit: vi.fn().mockResolvedValue(null),
  },
}))

vi.mock('../../../services/rbac-resolver.service.js', () => ({
  rbacResolverService: {
    resolveUserRbac: vi.fn().mockResolvedValue({
      email: 'test@example.org',
      groups: [],
      roles: [],
      permissions: [],
    }),
  },
}))

vi.mock('../../../services/user-groups.service.js', () => ({
  userGroupsService: {},
}))

vi.mock('../../../services/opa.service.js', () => ({
  opalService: { getUserInfo: vi.fn() },
}))

vi.mock('../../../config/env.js', () => ({
  env: { APP_NAME: 'jinbe' },
}))

import { AdminController } from '../../../controllers/admin.controller.js'
import { kratosService, KratosApiError } from '../../../services/kratos.service.js'
import { rbacService } from '../../../services/rbac.service.js'
import { auditEventService } from '../../../services/audit-event.service.js'

// ── Helpers ──────────────────────────────────────────────────────────

function createMockRequest(
  email: string,
  body: { organizations: string[] } | unknown,
): FastifyRequest<{
  Params: { email: string }
  Body: { organizations: string[] }
}> {
  return {
    params: { email },
    body,
    userContext: { email: 'admin@example.org' },
    ip: '10.0.0.1',
    log: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  } as unknown as FastifyRequest<{
    Params: { email: string }
    Body: { organizations: string[] }
  }>
}

function createMockReply(): FastifyReply & {
  _statusCode?: number
  _body?: unknown
} {
  const reply = {
    _statusCode: 200 as number | undefined,
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
  return reply as unknown as FastifyReply & {
    _statusCode?: number
    _body?: unknown
  }
}

// ── Tests ────────────────────────────────────────────────────────────

describe('AdminController — PUT /api/admin/users/:email/organizations', () => {
  let controller: AdminController

  beforeEach(() => {
    vi.clearAllMocks()
    controller = new AdminController()
  })

  it('returns 200 with the updated organizations on success', async () => {
    vi.mocked(kratosService.updateUserOrganizations).mockResolvedValueOnce({
      ...DEFAULT_IDENTITY,
      metadata_admin: { organizations: [ORG_A, ORG_B] },
    })

    const request = createMockRequest('user@example.org', { organizations: [ORG_A, ORG_B] })
    const reply = createMockReply()

    await controller.updateUserOrganizations(request, reply)

    expect(reply.send).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 'user-123',
        email: 'user@example.org',
        organizations: [ORG_A, ORG_B],
        updatedAt: expect.any(String),
      }),
    )
    expect(reply._statusCode).toBe(200)
    expect(kratosService.updateUserOrganizations).toHaveBeenCalledWith('user@example.org', [
      ORG_A,
      ORG_B,
    ])
  })

  it('accepts an empty organizations array (removes all memberships)', async () => {
    vi.mocked(kratosService.updateUserOrganizations).mockResolvedValueOnce({
      ...DEFAULT_IDENTITY,
      metadata_admin: { organizations: [] },
    })

    const request = createMockRequest('user@example.org', { organizations: [] })
    const reply = createMockReply()

    await controller.updateUserOrganizations(request, reply)

    expect(reply._statusCode).toBe(200)
    expect(kratosService.updateUserOrganizations).toHaveBeenCalledWith('user@example.org', [])
  })

  it('returns 400 when an entry is not a valid UUID', async () => {
    const request = createMockRequest('user@example.org', { organizations: ['not-a-uuid'] })
    const reply = createMockReply()

    await controller.updateUserOrganizations(request, reply)

    expect(reply._statusCode).toBe(400)
    expect(kratosService.updateUserOrganizations).not.toHaveBeenCalled()
  })

  it('returns 400 when the body is missing the organizations field', async () => {
    const request = createMockRequest('user@example.org', {})
    const reply = createMockReply()

    await controller.updateUserOrganizations(request, reply)

    expect(reply._statusCode).toBe(400)
    expect(kratosService.updateUserOrganizations).not.toHaveBeenCalled()
  })

  it('returns 404 when the email does not match an identity', async () => {
    vi.mocked(kratosService.updateUserOrganizations).mockRejectedValueOnce(
      new KratosApiError(404, 'User not found: ghost@example.org'),
    )

    const request = createMockRequest('ghost@example.org', { organizations: [ORG_A] })
    const reply = createMockReply()

    await controller.updateUserOrganizations(request, reply)

    expect(reply._statusCode).toBe(404)
    expect(reply._body).toEqual({
      error: 'Not Found',
      message: 'User not found: ghost@example.org',
    })
  })

  it('emits a user.organizations_changed audit event with the requested orgs', async () => {
    vi.mocked(kratosService.updateUserOrganizations).mockResolvedValueOnce({
      ...DEFAULT_IDENTITY,
      metadata_admin: { organizations: [ORG_A, ORG_C] },
    })

    const request = createMockRequest('user@example.org', { organizations: [ORG_A, ORG_C] })
    const reply = createMockReply()

    await controller.updateUserOrganizations(request, reply)

    expect(auditEventService.emit).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'user.organizations_changed',
        target: expect.objectContaining({ type: 'user', id: 'user-123' }),
        actor: expect.objectContaining({ email: 'admin@example.org' }),
        details: expect.objectContaining({
          email: 'user@example.org',
          organizations: [ORG_A, ORG_C],
        }),
        source: 'jinbe-api',
      }),
    )
  })

  it('triggers an OPAL refresh after a successful update', async () => {
    vi.mocked(kratosService.updateUserOrganizations).mockResolvedValueOnce({
      ...DEFAULT_IDENTITY,
      metadata_admin: { organizations: [ORG_A] },
    })

    const request = createMockRequest('user@example.org', { organizations: [ORG_A] })
    const reply = createMockReply()

    await controller.updateUserOrganizations(request, reply)

    expect(rbacService.notifyBindingsChanged).toHaveBeenCalledWith(
      'user_organizations_changed',
      expect.objectContaining({ email: 'admin@example.org', ip: '10.0.0.1' }),
    )
  })

  it('still succeeds and returns 200 when the OPAL refresh fails (best-effort)', async () => {
    vi.mocked(kratosService.updateUserOrganizations).mockResolvedValueOnce({
      ...DEFAULT_IDENTITY,
      metadata_admin: { organizations: [ORG_A] },
    })
    vi.mocked(rbacService.notifyBindingsChanged).mockRejectedValueOnce(
      new Error('opal-server unreachable'),
    )

    const request = createMockRequest('user@example.org', { organizations: [ORG_A] })
    const reply = createMockReply()

    await controller.updateUserOrganizations(request, reply)

    expect(reply._statusCode).toBe(200)
  })
})

describe('AdminController — GET /api/admin/users/:email/organizations', () => {
  let controller: AdminController

  beforeEach(() => {
    vi.clearAllMocks()
    controller = new AdminController()
  })

  it('returns organizations array + legacy organization_id pointer', async () => {
    vi.mocked(kratosService.findByEmail).mockResolvedValueOnce({
      ...DEFAULT_IDENTITY,
      organization_id: ORG_B,
      metadata_admin: { organizations: [ORG_A] },
    })

    const request = createMockRequest('user@example.org', { organizations: [] })
    const reply = createMockReply()

    await controller.getUserOrganizations(request, reply)

    expect(reply.send).toHaveBeenCalledWith({
      email: 'user@example.org',
      organizations: [ORG_A],
      organization_id: ORG_B,
    })
  })

  it('returns empty array + null when neither field is set', async () => {
    vi.mocked(kratosService.findByEmail).mockResolvedValueOnce({
      ...DEFAULT_IDENTITY,
      organization_id: null,
      metadata_admin: null,
    })

    const request = createMockRequest('user@example.org', { organizations: [] })
    const reply = createMockReply()

    await controller.getUserOrganizations(request, reply)

    expect(reply.send).toHaveBeenCalledWith({
      email: 'user@example.org',
      organizations: [],
      organization_id: null,
    })
  })

  it('returns 404 when the email has no identity', async () => {
    vi.mocked(kratosService.findByEmail).mockResolvedValueOnce(null)

    const request = createMockRequest('ghost@example.org', { organizations: [] })
    const reply = createMockReply()

    await controller.getUserOrganizations(request, reply)

    expect(reply._statusCode).toBe(404)
    expect(reply._body).toEqual({
      error: 'Not Found',
      message: 'User not found: ghost@example.org',
    })
  })
})
