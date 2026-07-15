import { describe, it, expect, beforeEach, vi } from 'vitest'

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getUserGroups: vi.fn().mockResolvedValue([]),
    updateUserGroups: vi.fn().mockResolvedValue(undefined),
  },
}))

vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: {
    isAdminPowerGroup: vi.fn().mockResolvedValue(false),
    // Default: the group under test is NOT global (a plain "admins" group), so
    // the wildcard_in_org path keeps its org-"*" behaviour. Cases exercising a
    // global group override this per-test.
    groupGrantsGlobalPower: vi.fn().mockResolvedValue(false),
    assertSuperAdmin: vi.fn().mockResolvedValue(undefined),
    findPrivilegedGroupRequiringMFA: vi.fn().mockResolvedValue(null),
    notifyBindingsChanged: vi.fn().mockResolvedValue(undefined),
  },
}))

vi.mock('../../../services/opa.service.js', () => ({
  opaService: {
    // org-scoped grant decision; default deny (fail-closed). Cases set it per-test.
    canGrant: vi.fn().mockResolvedValue(false),
  },
}))

vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: {
    emit: vi.fn().mockResolvedValue(undefined),
  },
}))

import { userGroupsService, type ResolvedIdentity } from '../../../services/user-groups.service.js'
import { kratosService } from '../../../services/kratos.service.js'
import { rbacService } from '../../../services/rbac.service.js'
import { opaService } from '../../../services/opa.service.js'
import { auditEventService } from '../../../services/audit-event.service.js'

const IDENTITY: ResolvedIdentity = {
  id: 'user-123',
  email: 'target@example.com',
  organizationId: 'org-1',
}

const ACTOR = { email: 'actor@example.com', ip: '127.0.0.1' }

describe('userGroupsService.applyGroupUpdate — happy path', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(kratosService.getUserGroups).mockResolvedValue([])
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue(null)
  })

  it('returns ok=true with enriched response shape and persists groups', async () => {
    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.response).toMatchObject({
        id: 'user-123',
        organizationId: 'org-1',
        email: 'target@example.com',
        groups: ['users'],
      })
      expect(typeof result.response.updatedAt).toBe('string')
    }
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['users'])
  })

  it('defaults to ["users"] when newGroups is empty', async () => {
    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: [],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['users'])
  })

  it('emits audit event with extra details merged into details object', async () => {
    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
      auditExtraDetails: { organizationId: 'org-1' },
    })

    expect(auditEventService.emit).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'organization_user.groups_changed',
        target: { type: 'user', id: 'user-123' },
        details: expect.objectContaining({
          organizationId: 'org-1',
          oldGroups: [],
          newGroups: ['users'],
        }),
      })
    )
  })

  it('calls notifyBindingsChanged with the actor', async () => {
    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(rbacService.notifyBindingsChanged).toHaveBeenCalledWith('groups_changed', ACTOR)
  })

  it('skips priv-escalation and MFA gates when newlyAdded is empty (groups unchanged)', async () => {
    vi.mocked(kratosService.getUserGroups).mockResolvedValueOnce(['users'])

    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(rbacService.isAdminPowerGroup).not.toHaveBeenCalled()
    expect(rbacService.findPrivilegedGroupRequiringMFA).not.toHaveBeenCalled()
    expect(kratosService.updateUserGroups).toHaveBeenCalled()
  })
})

describe('userGroupsService.applyGroupUpdate — super_admin_required policy', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(kratosService.getUserGroups).mockResolvedValue([])
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(true)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue(null)
  })

  it('returns 422 privilege_escalation_blocked when assertSuperAdmin throws 403', async () => {
    vi.mocked(rbacService.assertSuperAdmin).mockRejectedValueOnce(
      Object.assign(new Error('Only super_admins may assign group ...'), { statusCode: 403 })
    )

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result).toEqual({
      ok: false,
      status: 422,
      body: expect.objectContaining({
        error: 'privilege_escalation_blocked',
        targetEmail: 'target@example.com',
        blockingGroup: 'admins',
      }),
    })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('returns 401 when assertSuperAdmin throws 401 (missing actor email)', async () => {
    vi.mocked(rbacService.assertSuperAdmin).mockRejectedValueOnce(
      Object.assign(new Error('Authentication required'), { statusCode: 401 })
    )

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.status).toBe(401)
  })

  it('proceeds to MFA gate when actor IS super_admin', async () => {
    vi.mocked(rbacService.assertSuperAdmin).mockResolvedValueOnce(undefined)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue('admins')

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result).toEqual({
      ok: false,
      status: 422,
      body: expect.objectContaining({
        error: 'mfa_required',
        targetEmail: 'target@example.com',
        targetGroups: ['admins'],
      }),
    })
  })
})

describe('userGroupsService.applyGroupUpdate — wildcard_in_org policy', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(kratosService.getUserGroups).mockResolvedValue([])
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(true)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue(null)
  })

  it('returns 422 privilege_escalation_blocked when OPA can_grant denies', async () => {
    // Scoped (non-global) admin group; the OPA delegation policy refuses
    // (containment / admin-authority / service-scope not satisfied).
    vi.mocked(opaService.canGrant).mockResolvedValue(false)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result).toEqual({
      ok: false,
      status: 422,
      body: expect.objectContaining({
        error: 'privilege_escalation_blocked',
        blockingGroup: 'admins',
      }),
    })
    // Actor's permissions come from OPA (by email) — never from the caller.
    expect(opaService.canGrant).toHaveBeenCalledWith({
      actor: { email: 'actor@example.com' },
      target_group: 'admins',
      target_org: 'org-1',
    })
    expect(rbacService.assertSuperAdmin).not.toHaveBeenCalled()
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('denies without calling OPA when the actor has no email (fail-closed)', async () => {
    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['admins'],
      actor: { ip: '127.0.0.1' },
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result).toMatchObject({ ok: false, status: 422, body: { error: 'privilege_escalation_blocked' } })
    expect(opaService.canGrant).not.toHaveBeenCalled()
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('allows the grant when OPA can_grant is true (MFA gate still applies)', async () => {
    vi.mocked(opaService.canGrant).mockResolvedValue(true)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue('admins')

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result).toMatchObject({
      ok: false,
      status: 422,
      body: { error: 'mfa_required' },
    })
  })

  it('permits a scoped admin grant when OPA can_grant is true and no MFA blocker', async () => {
    vi.mocked(opaService.canGrant).mockResolvedValue(true)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue(null)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result.ok).toBe(true)
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['admins'])
  })

  it('routes a GLOBAL-power group to the super_admin backstop, never to OPA can_grant', async () => {
    // J1: an org "*" wildcard must not mint a global super_admin. The global
    // group short-circuits to the super_admin authority check before can_grant.
    vi.mocked(rbacService.groupGrantsGlobalPower).mockResolvedValue(true)
    vi.mocked(rbacService.assertSuperAdmin).mockRejectedValueOnce(
      Object.assign(new Error('Only super_admins may assign group ...'), { statusCode: 403 }),
    )

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['super_admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result).toMatchObject({ ok: false, status: 422, body: { error: 'privilege_escalation_blocked' } })
    expect(rbacService.assertSuperAdmin).toHaveBeenCalled()
    expect(opaService.canGrant).not.toHaveBeenCalled()
  })

  it('happy path — non-admin group skips the delegation gate entirely', async () => {
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result.ok).toBe(true)
    expect(opaService.canGrant).not.toHaveBeenCalled()
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['users'])
  })
})

describe('userGroupsService.applyGroupUpdate — MFA gate', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(kratosService.getUserGroups).mockResolvedValue([])
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
  })

  it('returns 422 mfa_required when findPrivilegedGroupRequiringMFA returns a blocker', async () => {
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValueOnce('super_admins')

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['super_admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result).toMatchObject({
      ok: false,
      status: 422,
      body: {
        error: 'mfa_required',
        targetEmail: 'target@example.com',
        targetGroups: ['super_admins'],
      },
    })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })
})
