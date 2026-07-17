import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

const { DEFAULT_IDENTITY } = vi.hoisted(() => ({
  DEFAULT_IDENTITY: {
    id: 'user-123',
    schema_id: 'default',
    state: 'active',
    traits: { email: 'user@example.com' },
    organization_id: null,
    metadata_admin: { groups: [] },
    metadata_public: {},
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
}))

// The Redis mutex is infrastructure; these units validate the group-update
// guard/MFA logic, not locking. Passthrough so no Redis is required (the lock
// has its own test).
vi.mock('../../../services/redis-lock.js', () => ({
  withRedisLock: (_name: string, fn: () => unknown) => fn(),
}))

// Mock dependencies
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getUserGroups: vi.fn(),
    updateUserGroups: vi.fn(),
    // updateUserGroups now resolves the identity up-front (fail-closed)
    // before delegating to userGroupsService. Default mock returns a
    // valid identity so the happy paths can flow through; tests can
    // override to null/throw to exercise 404 / error propagation.
    findByEmail: vi.fn().mockResolvedValue(DEFAULT_IDENTITY),
    hasMFA: vi.fn().mockResolvedValue(false),
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
    // MFA-gate helper. Default returns null (no privileged group blocked);
    // individual tests override to simulate refusal.
    findPrivilegedGroupRequiringMFA: vi.fn().mockResolvedValue(null),
    // Privilege-escalation guard helpers. Default to non-privileged group +
    // super_admin actor so the guard always falls through to the MFA gate
    // unless a specific test overrides the behaviour.
    isAdminPowerGroup: vi.fn().mockResolvedValue(false),
    assertSuperAdmin: vi.fn().mockResolvedValue(undefined),
  },
}))

vi.mock('../../../services/opa.service.js', () => ({
  opalService: {
    getUserInfo: vi.fn(),
  },
}))

vi.mock('../../../config/env.js', () => ({
  env: {
    APP_NAME: 'jinbe',
  },
}))

// Mock rbacResolverService (new direct resolver)
vi.mock('../../../services/rbac-resolver.service.js', () => ({
  rbacResolverService: {
    resolveUserRbac: vi.fn().mockResolvedValue({
      email: 'test@example.com',
      groups: [],
      roles: [],
      permissions: [],
    }),
  },
}))

import { AdminController } from '../../../controllers/admin.controller.js'
import { kratosService, KratosApiError } from '../../../services/kratos.service.js'
import { rbacService } from '../../../services/rbac.service.js'

// Helper to create mock request
function createMockRequest(
  email: string,
  body?: { groups: string[] }
): FastifyRequest<{
  Params: { email: string }
  Body: { groups: string[] }
}> {
  return {
    params: { email },
    body: body || { groups: [] },
    userContext: { email: 'admin@example.com' },
    log: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  } as unknown as FastifyRequest<{
    Params: { email: string }
    Body: { groups: string[] }
  }>
}

// Helper to create mock reply
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

describe('AdminController - User Groups', () => {
  let controller: AdminController

  beforeEach(() => {
    vi.clearAllMocks()
    controller = new AdminController()
  })

  // ===========================================================================
  // getUserGroups
  // ===========================================================================
  describe('getUserGroups', () => {
    it('should return user groups and available groups', async () => {
      vi.mocked(kratosService.getUserGroups).mockResolvedValueOnce(['devs', 'users'])
      vi.mocked(rbacService.getAvailableGroups).mockResolvedValueOnce([
        'super_admins',
        'admins',
        'devs',
        'users',
      ])

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await controller.getUserGroups(request, reply)

      expect(reply.send).toHaveBeenCalledWith({
        email: 'user@example.com',
        groups: ['devs', 'users'],
        availableGroups: ['super_admins', 'admins', 'devs', 'users'],
      })
    })

    it('should return 404 when user not found', async () => {
      vi.mocked(kratosService.getUserGroups).mockRejectedValueOnce(
        new KratosApiError(404, 'User not found: nonexistent@example.com')
      )

      const request = createMockRequest('nonexistent@example.com')
      const reply = createMockReply()

      await controller.getUserGroups(request, reply)

      expect(reply._statusCode).toBe(404)
      expect(reply._body).toEqual({
        error: 'Not Found',
        message: 'User not found: nonexistent@example.com',
      })
    })

    it('should propagate unexpected errors', async () => {
      vi.mocked(kratosService.getUserGroups).mockRejectedValueOnce(
        new Error('Database connection failed')
      )

      const request = createMockRequest('user@example.com')
      const reply = createMockReply()

      await expect(controller.getUserGroups(request, reply)).rejects.toThrow(
        'Database connection failed'
      )
    })
  })

  // ===========================================================================
  // updateUserGroups
  // ===========================================================================
  describe('updateUserGroups', () => {
    it('should update user groups with valid groups', async () => {
      vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
      vi.mocked(kratosService.updateUserGroups).mockResolvedValueOnce({
        id: 'user-123',
        schema_id: 'default',
        state: 'active',
        traits: { email: 'user@example.com' },
        metadata_admin: { groups: ['admins', 'devs'] },
        metadata_public: {},
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      })

      const request = createMockRequest('user@example.com', {
        groups: ['admins', 'devs'],
      })
      const reply = createMockReply()

      await controller.updateUserGroups(request, reply)

      expect(rbacService.validateGroups).toHaveBeenCalledWith(['admins', 'devs'])
      expect(kratosService.updateUserGroups).toHaveBeenCalledWith('user@example.com', [
        'admins',
        'devs',
      ])
      expect(reply._body).toMatchObject({
        email: 'user@example.com',
        groups: ['admins', 'devs'],
      })
      expect((reply._body as { updatedAt: string }).updatedAt).toBeDefined()
    })

    it('should default to ["users"] when empty groups array', async () => {
      vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
      vi.mocked(kratosService.updateUserGroups).mockResolvedValueOnce({
        id: 'user-123',
        schema_id: 'default',
        state: 'active',
        traits: { email: 'user@example.com' },
        metadata_admin: { groups: ['users'] },
        metadata_public: {},
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      })

      const request = createMockRequest('user@example.com', { groups: [] })
      const reply = createMockReply()

      await controller.updateUserGroups(request, reply)

      expect(kratosService.updateUserGroups).toHaveBeenCalledWith('user@example.com', ['users'])
      expect((reply._body as { groups: string[] }).groups).toEqual(['users'])
    })

    it('should return 400 when groups are invalid', async () => {
      vi.mocked(rbacService.validateGroups).mockRejectedValueOnce(
        new Error(
          'Invalid groups: fake_group. Available groups: super_admins, admins, devs, users'
        )
      )

      const request = createMockRequest('user@example.com', {
        groups: ['fake_group'],
      })
      const reply = createMockReply()

      await controller.updateUserGroups(request, reply)

      expect(reply._statusCode).toBe(400)
      expect(reply._body).toEqual({
        error: 'Bad Request',
        message:
          'Invalid groups: fake_group. Available groups: super_admins, admins, devs, users',
      })
    })

    it('should return 404 when user not found', async () => {
      vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
      vi.mocked(kratosService.updateUserGroups).mockRejectedValueOnce(
        new KratosApiError(404, 'User not found: nonexistent@example.com')
      )

      const request = createMockRequest('nonexistent@example.com', {
        groups: ['users'],
      })
      const reply = createMockReply()

      await controller.updateUserGroups(request, reply)

      expect(reply._statusCode).toBe(404)
      expect(reply._body).toEqual({
        error: 'Not Found',
        message: 'User not found: nonexistent@example.com',
      })
    })

    it('should log update with admin email', async () => {
      vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
      vi.mocked(kratosService.updateUserGroups).mockResolvedValueOnce({
        id: 'user-123',
        schema_id: 'default',
        state: 'active',
        traits: { email: 'user@example.com' },
        metadata_admin: { groups: ['devs'] },
        metadata_public: {},
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      })

      const request = createMockRequest('user@example.com', { groups: ['devs'] })
      const reply = createMockReply()

      await controller.updateUserGroups(request, reply)

      expect(request.log.info).toHaveBeenCalledWith(
        { email: 'user@example.com', groups: ['devs'], adminEmail: 'admin@example.com' },
        'Updating user groups'
      )
    })

    it('should propagate unexpected errors', async () => {
      vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
      vi.mocked(kratosService.updateUserGroups).mockRejectedValueOnce(
        new Error('Network timeout')
      )

      const request = createMockRequest('user@example.com', { groups: ['devs'] })
      const reply = createMockReply()

      await expect(controller.updateUserGroups(request, reply)).rejects.toThrow(
        'Network timeout'
      )
    })

    // =========================================================================
    // Privilege-escalation guard
    // src/controllers/admin.controller.ts:343-365 — runs BEFORE the MFA gate.
    // Refuses any non-super_admin actor that tries to add a group whose
    // membership confers admin or super_admin power. kuma's toast logic keys
    // off the literal `error: "privilege_escalation_blocked"` code, so the
    // string is locked down here to prevent accidental rename.
    // =========================================================================
    describe('updateUserGroups - privilege escalation guard (admin.controller.ts:343-365)', () => {
      it('returns 422 with error="privilege_escalation_blocked" when actor lacks super_admin and adds an admin-power group (admin.controller.ts:355-361)', async () => {
        vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
        // 'super_admins' is admin-power
        vi.mocked(rbacService.isAdminPowerGroup).mockImplementation(async (g: string) =>
          g === 'super_admins'
        )
        // Actor is a regular admin, not super_admin → assertSuperAdmin throws 403
        const err = Object.assign(
          new Error("Only super_admins may assign group 'super_admins' (grants admin privileges)"),
          { statusCode: 403 },
        )
        vi.mocked(rbacService.assertSuperAdmin).mockRejectedValueOnce(err)

        const request = createMockRequest('victim@example.com', {
          groups: ['super_admins'],
        })
        const reply = createMockReply()

        await controller.updateUserGroups(request, reply)

        expect(reply._statusCode).toBe(422)
        expect(reply._body).toMatchObject({
          error: 'privilege_escalation_blocked',
          targetEmail: 'victim@example.com',
          blockingGroup: 'super_admins',
        })
        expect((reply._body as { hint: string }).hint).toMatch(/super_admin/i)
        // Mutation must NOT have been performed
        expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
      })

      it('returns 401 (not 422) when actor email is missing — assertSuperAdmin throws 401 (rbac.service.ts:165-168)', async () => {
        vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
        vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValueOnce(true)
        const err = Object.assign(
          new Error('Authentication required for this operation'),
          { statusCode: 401 },
        )
        vi.mocked(rbacService.assertSuperAdmin).mockRejectedValueOnce(err)

        const request = createMockRequest('victim@example.com', {
          groups: ['super_admins'],
        })
        // Strip userContext so the controller's actor is undefined
        delete (request as { userContext?: unknown }).userContext
        const reply = createMockReply()

        await controller.updateUserGroups(request, reply)

        expect(reply._statusCode).toBe(401)
        expect((reply._body as { error: string }).error).toBe('privilege_escalation_blocked')
        expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
      })

      it('falls through to MFA gate when actor IS super_admin (admin.controller.ts:347-350)', async () => {
        vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
        vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValueOnce(true)
        // assertSuperAdmin resolves → guard is satisfied
        vi.mocked(rbacService.assertSuperAdmin).mockResolvedValueOnce(undefined)
        // Target identity has MFA so the MFA gate also passes
        vi.mocked(kratosService.findByEmail).mockResolvedValueOnce({
          id: 'identity-with-mfa',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'victim@example.com' },
          credentials: { totp: {} } as Record<string, unknown>,
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        } as never)
        vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValueOnce(null)
        vi.mocked(kratosService.updateUserGroups).mockResolvedValueOnce({
          id: 'identity-with-mfa',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'victim@example.com' },
          metadata_admin: { groups: ['super_admins'] },
          metadata_public: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        })

        const request = createMockRequest('victim@example.com', {
          groups: ['super_admins'],
        })
        const reply = createMockReply()

        await controller.updateUserGroups(request, reply)

        expect(rbacService.assertSuperAdmin).toHaveBeenCalled()
        expect(kratosService.updateUserGroups).toHaveBeenCalledWith(
          'victim@example.com',
          ['super_admins'],
        )
      })

      it('skips guard entirely when newlyAdded group is not admin-power (admin.controller.ts:344-345)', async () => {
        vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
        vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
        vi.mocked(kratosService.updateUserGroups).mockResolvedValueOnce({
          id: 'user-123',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'user@example.com' },
          metadata_admin: { groups: ['devs'] },
          metadata_public: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        })

        const request = createMockRequest('user@example.com', { groups: ['devs'] })
        const reply = createMockReply()

        await controller.updateUserGroups(request, reply)

        expect(rbacService.assertSuperAdmin).not.toHaveBeenCalled()
        expect(kratosService.updateUserGroups).toHaveBeenCalledWith(
          'user@example.com',
          ['devs'],
        )
      })
    })

    // =========================================================================
    // MFA gate
    // src/controllers/admin.controller.ts:367-397 — refuses to add a target
    // identity to a privileged group when that identity has no second factor.
    // The 422 status code is deliberate (see comment in source) and kuma's
    // toast logic keys off `error: "mfa_required"`.
    // =========================================================================
    describe('updateUserGroups - MFA gate (admin.controller.ts:367-397)', () => {
      it('returns 422 with error="mfa_required" when adding target without MFA to a privileged group (admin.controller.ts:388-395)', async () => {
        vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
        // Privilege-escalation guard does not block (e.g. actor is super_admin)
        vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
        // MFA gate finds an identity, then refuses
        vi.mocked(kratosService.findByEmail).mockResolvedValueOnce({
          id: 'identity-no-mfa',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'fresh@example.com' },
          credentials: {} as Record<string, unknown>,
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        } as never)
        vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValueOnce(
          'super_admins',
        )

        const request = createMockRequest('fresh@example.com', {
          groups: ['super_admins'],
        })
        const reply = createMockReply()

        await controller.updateUserGroups(request, reply)

        expect(reply._statusCode).toBe(422)
        expect(reply._body).toMatchObject({
          error: 'mfa_required',
          targetEmail: 'fresh@example.com',
          targetGroups: ['super_admins'],
        })
        expect((reply._body as { message: string }).message).toMatch(/super_admins/)
        expect((reply._body as { hint: string }).hint).toMatch(/Authenticator/i)
        expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
      })

      it('proceeds with mutation when target identity has MFA enrolled (admin.controller.ts:379-380)', async () => {
        vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
        vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
        vi.mocked(kratosService.findByEmail).mockResolvedValueOnce({
          id: 'identity-mfa-yes',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'mfa@example.com' },
          credentials: { totp: {}, webauthn: {}, lookup_secret: {} } as Record<string, unknown>,
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        } as never)
        // No blocker → gate passes
        vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValueOnce(null)
        vi.mocked(kratosService.updateUserGroups).mockResolvedValueOnce({
          id: 'identity-mfa-yes',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'mfa@example.com' },
          metadata_admin: { groups: ['super_admins'] },
          metadata_public: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        })

        const request = createMockRequest('mfa@example.com', {
          groups: ['super_admins'],
        })
        const reply = createMockReply()

        await controller.updateUserGroups(request, reply)

        expect(kratosService.updateUserGroups).toHaveBeenCalledWith(
          'mfa@example.com',
          ['super_admins'],
        )
        // Successful response shape
        expect(reply._body).toMatchObject({
          email: 'mfa@example.com',
          groups: ['super_admins'],
        })
      })

      it('skips MFA gate when newlyAdded contains only non-privileged groups (admin.controller.ts:372)', async () => {
        vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
        vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
        // findByEmail must NOT be invoked because newlyAdded.length is checked
        // first AND findPrivilegedGroupRequiringMFA receives a list that won't
        // produce a blocker; we still assert the gate doesn't refuse.
        vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValueOnce(null)
        vi.mocked(kratosService.updateUserGroups).mockResolvedValueOnce({
          id: 'user-123',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'user@example.com' },
          metadata_admin: { groups: ['devs', 'viewers'] },
          metadata_public: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        })

        const request = createMockRequest('user@example.com', {
          groups: ['devs', 'viewers'],
        })
        const reply = createMockReply()

        await controller.updateUserGroups(request, reply)

        expect(kratosService.updateUserGroups).toHaveBeenCalledWith(
          'user@example.com',
          ['devs', 'viewers'],
        )
        expect(reply._body).toMatchObject({
          email: 'user@example.com',
          groups: ['devs', 'viewers'],
        })
      })

      it('returns 404 when identity lookup returns null — fail-closed identity resolution', async () => {
        vi.mocked(rbacService.validateGroups).mockResolvedValueOnce(undefined)
        vi.mocked(kratosService.findByEmail).mockResolvedValueOnce(null)

        const request = createMockRequest('missing@example.com', {
          groups: ['super_admins'],
        })
        const reply = createMockReply()

        await controller.updateUserGroups(request, reply)

        expect(reply._statusCode).toBe(404)
        expect(reply._body).toMatchObject({ error: 'Not Found' })
        // Mutation MUST NOT proceed without a resolved identity, otherwise
        // the MFA gate would be bypassed when Kratos is degraded.
        expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
        expect(rbacService.findPrivilegedGroupRequiringMFA).not.toHaveBeenCalled()
      })
    })
  })
})
