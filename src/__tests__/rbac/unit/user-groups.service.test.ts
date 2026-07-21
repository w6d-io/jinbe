import { describe, it, expect, beforeEach, vi } from 'vitest'

// The Redis mutex is infrastructure; these units validate the gate logic, not
// locking (the lock has its own test). Passthrough so no Redis is required.
vi.mock('../../../services/redis-lock.js', () => ({
  withRedisLock: (_name: string, fn: () => unknown) => fn(),
}))

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
    // Base group `users` is empty by default → exempt from the delegation gate.
    isEmptyGroup: vi.fn().mockResolvedValue(true),
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

// A freshly-2FA'd actor: passes the R2 step-up gate so the pre-existing privilege
// tests exercise their intended paths. Step-up-specific cases override this.
const ACTOR = { email: 'actor@example.com', ip: '127.0.0.1', aal: 'aal2', authenticatedAt: new Date() }

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

describe('userGroupsService.applyGroupUpdate — MFA step-up (R2)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(kratosService.getUserGroups).mockResolvedValue([])
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(true) // target group is privileged
    vi.mocked(rbacService.assertSuperAdmin).mockResolvedValue(undefined)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue(null)
  })

  const assignPrivileged = (actor: Record<string, unknown>) =>
    userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['admins'],
      actor,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

  it('blocks a privileged assignment when the actor is only AAL1 (no second factor)', async () => {
    const result = await assignPrivileged({ email: 'a@x.io', ip: '1', aal: 'aal1', authenticatedAt: new Date() })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(422)
      expect(result.body).toMatchObject({ error: 'reauth_required' })
    }
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('blocks when the AAL2 factor is older than the 15-minute step-up window', async () => {
    const stale = new Date(Date.now() - 20 * 60 * 1000)
    const result = await assignPrivileged({ email: 'a@x.io', ip: '1', aal: 'aal2', authenticatedAt: stale })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.body).toMatchObject({ error: 'reauth_required' })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('fails closed when AAL is absent', async () => {
    const result = await assignPrivileged({ email: 'a@x.io', ip: '1' })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.body).toMatchObject({ error: 'reauth_required' })
  })

  it('allows a privileged assignment with a fresh AAL2 factor', async () => {
    const result = await assignPrivileged({ email: 'a@x.io', ip: '1', aal: 'aal2', authenticatedAt: new Date() })
    expect(result.ok).toBe(true)
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['admins'])
  })

  it('does NOT require step-up for a non-privileged change (demotion to base group)', async () => {
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: { email: 'a@x.io', ip: '1', aal: 'aal1', authenticatedAt: new Date() }, // AAL1 is fine: nothing gated
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })
    expect(result.ok).toBe(true)
  })
})

describe('userGroupsService.applyGroupUpdate — org_admins flag gate', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(kratosService.getUserGroups).mockResolvedValue([])
    // The flag group is EMPTY → NOT admin-power. Without the explicit guard the
    // global path (isAdminPowerGroup) would skip the super_admin check for it.
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue(null)
  })

  it('global path: assigning org_admins is super_admin-gated even though it is not admin-power', async () => {
    vi.mocked(rbacService.assertSuperAdmin).mockRejectedValueOnce(
      Object.assign(new Error('only super_admins may assign org_admins'), { statusCode: 403 }),
    )

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['org_admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(422)
      expect(result.body).toMatchObject({ error: 'privilege_escalation_blocked', blockingGroup: 'org_admins' })
    }
    expect(rbacService.assertSuperAdmin).toHaveBeenCalled()
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('global path: a super_admin CAN assign org_admins', async () => {
    vi.mocked(rbacService.assertSuperAdmin).mockResolvedValue(undefined)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['org_admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(true)
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['org_admins'])
  })

  it('org-scoped path: org_admins is put to can_grant (denied), never waved through as an empty group', async () => {
    // isEmptyGroup(org_admins) is true, but the wildcard_in_org exemption keys on
    // the base group NAME ("users"), so org_admins IS submitted to can_grant —
    // which denies it (0 perms → not bundle-containable).
    vi.mocked(rbacService.isEmptyGroup).mockResolvedValue(true)
    vi.mocked(rbacService.groupGrantsGlobalPower).mockResolvedValue(false)
    vi.mocked(opaService.canGrant).mockResolvedValue(false)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['org_admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.body).toMatchObject({ error: 'privilege_escalation_blocked', blockingGroup: 'org_admins' })
    }
    expect(opaService.canGrant).toHaveBeenCalledWith(expect.objectContaining({ target_group: 'org_admins' }))
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
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

  it('does NOT gate REMOVALS on the super_admin endpoint (a super_admin may freely remove)', async () => {
    // A super_admin drops a privileged group. Removals are not gated here — the
    // endpoint is super_admin-gated at the route and a super_admin can remove
    // anything. Only *added* admin-power groups reach assertSuperAdmin.
    vi.mocked(kratosService.getUserGroups).mockResolvedValue(['admins', 'users'])

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(rbacService.assertSuperAdmin).not.toHaveBeenCalled()
    expect(result.ok).toBe(true)
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['users'])
  })
})

describe('userGroupsService.applyGroupUpdate — wildcard_in_org policy', () => {
  beforeEach(() => {
    // clearAllMocks resets call history but NOT implementations, so re-assert
    // the override-prone mocks' defaults here to prevent per-test state leaking
    // across cases (e.g. a global-group test leaving groupGrantsGlobalPower true).
    vi.clearAllMocks()
    vi.mocked(kratosService.getUserGroups).mockResolvedValue([])
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(true)
    vi.mocked(rbacService.groupGrantsGlobalPower).mockResolvedValue(false)
    vi.mocked(rbacService.isEmptyGroup).mockResolvedValue(true)
    vi.mocked(rbacService.findPrivilegedGroupRequiringMFA).mockResolvedValue(null)
    vi.mocked(opaService.canGrant).mockResolvedValue(false)
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

  it('checks EVERY non-base group via can_grant, even a non-admin-power group (Finding 1)', async () => {
    // A multi-service read group (no `*`) is NOT admin-power, but must still be
    // put to can_grant — otherwise it would slip the single-service boundary.
    vi.mocked(rbacService.isAdminPowerGroup).mockResolvedValue(false)
    vi.mocked(opaService.canGrant).mockResolvedValue(false)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['viewers'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(opaService.canGrant).toHaveBeenCalledWith({
      actor: { email: 'actor@example.com' },
      target_group: 'viewers',
      target_org: 'org-1',
    })
    expect(result).toMatchObject({ ok: false, status: 422, body: { error: 'privilege_escalation_blocked' } })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('denies a GLOBAL-power group directly (defense-in-depth), without can_grant or super_admin routing', async () => {
    // Global groups are NEVER grantable on the org endpoint — for anyone. The
    // local groupGrantsGlobalPower check refuses independently of OPA, and does
    // NOT route to the super_admin path (that belongs to the global endpoint).
    vi.mocked(rbacService.groupGrantsGlobalPower).mockResolvedValue(true)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['super_admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result).toMatchObject({ ok: false, status: 422, body: { error: 'privilege_escalation_blocked' } })
    expect(opaService.canGrant).not.toHaveBeenCalled()
    expect(rbacService.assertSuperAdmin).not.toHaveBeenCalled()
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('exempts the base users group from the delegation gate (demotion allowed)', async () => {
    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result.ok).toBe(true)
    expect(opaService.canGrant).not.toHaveBeenCalled()
    expect(rbacService.groupGrantsGlobalPower).not.toHaveBeenCalled()
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['users'])
  })

  it('does NOT exempt a base group that has been redefined to confer roles', async () => {
    // Hardening: exemption is keyed on the group being empty, not its name. If
    // `users` were redefined to bind real roles, it is put to can_grant.
    vi.mocked(rbacService.isEmptyGroup).mockResolvedValue(false)
    vi.mocked(opaService.canGrant).mockResolvedValue(false)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(opaService.canGrant).toHaveBeenCalledWith({
      actor: { email: 'actor@example.com' },
      target_group: 'users',
      target_org: 'org-1',
    })
    expect(result).toMatchObject({ ok: false, status: 422, body: { error: 'privilege_escalation_blocked' } })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  // ── Symmetric containment: removals are gated too ─────────────────────────
  // A replace PUT that DROPS a group must clear the same can_grant authority as
  // an add. Otherwise a delegated org admin could strip a more-privileged
  // co-tenant (e.g. remove super_admins) simply by omitting the group.

  it('BLOCKS removing a group the actor cannot grant — no privilege stripping via replace PUT', async () => {
    // Target already holds a privileged group; actor submits {groups:["users"]}
    // to drop it. can_grant denies (actor cannot grant it) → the removal is refused.
    vi.mocked(kratosService.getUserGroups).mockResolvedValue(['stairfleet_admin', 'users'])
    vi.mocked(rbacService.groupGrantsGlobalPower).mockResolvedValue(false)
    vi.mocked(opaService.canGrant).mockResolvedValue(false)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(opaService.canGrant).toHaveBeenCalledWith({
      actor: { email: 'actor@example.com' },
      target_group: 'stairfleet_admin',
      target_org: 'org-1',
    })
    expect(result).toMatchObject({
      ok: false,
      status: 422,
      body: { error: 'privilege_escalation_blocked', blockingGroup: 'stairfleet_admin', operation: 'remove' },
    })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('BLOCKS removing a GLOBAL-power group on the org endpoint (defense-in-depth, no can_grant call)', async () => {
    vi.mocked(kratosService.getUserGroups).mockResolvedValue(['super_admins', 'users'])
    vi.mocked(rbacService.groupGrantsGlobalPower).mockResolvedValue(true)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result).toMatchObject({ ok: false, status: 422, body: { error: 'privilege_escalation_blocked' } })
    expect(opaService.canGrant).not.toHaveBeenCalled()
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })

  it('ALLOWS removing a group the actor CAN grant', async () => {
    vi.mocked(kratosService.getUserGroups).mockResolvedValue(['fleet-viewers', 'users'])
    vi.mocked(rbacService.groupGrantsGlobalPower).mockResolvedValue(false)
    vi.mocked(opaService.canGrant).mockResolvedValue(true)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(opaService.canGrant).toHaveBeenCalledWith({
      actor: { email: 'actor@example.com' },
      target_group: 'fleet-viewers',
      target_org: 'org-1',
    })
    expect(result.ok).toBe(true)
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['users'])
  })

  it('does NOT gate removal of the empty base users group', async () => {
    // Target holds fleet-viewers + the empty base group; drop only the base
    // group. Its removal confers/loses nothing, so it is exempt (isEmptyGroup).
    vi.mocked(kratosService.getUserGroups).mockResolvedValue(['fleet-viewers', 'users'])
    vi.mocked(rbacService.isEmptyGroup).mockResolvedValue(true)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['fleet-viewers'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(opaService.canGrant).not.toHaveBeenCalled()
    expect(result.ok).toBe(true)
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['fleet-viewers'])
  })

  it('FAILS CLOSED when the pre-image group read errors — no ungated strip (F1)', async () => {
    // The removal gate is computed from the pre-image (oldGroups). A transient
    // Kratos read error must NOT degrade into removed=[] followed by a replace
    // write that strips the target — refuse the update instead. getUserGroups
    // returns ['users'] for a user with no groups, so a throw is always a real
    // read failure, never "no groups".
    vi.mocked(kratosService.getUserGroups).mockRejectedValueOnce(new Error('kratos 503'))

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result).toMatchObject({ ok: false, status: 422, body: { error: 'groups_precondition_failed' } })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
    expect(opaService.canGrant).not.toHaveBeenCalled()
  })

  it('BLOCKS removing a MULTI-SERVICE group via the org endpoint (must be preserved, not stripped — F2)', async () => {
    // A group spanning services the org admin does not fully control cannot be
    // removed here: can_grant denies (grant_target_service requires a single
    // service == the org's). The frontend keeps such groups read-only and
    // re-submits them; a crafted PUT that drops one is refused (fail-safe).
    vi.mocked(kratosService.getUserGroups).mockResolvedValue(['cross-service-grp', 'users'])
    vi.mocked(rbacService.groupGrantsGlobalPower).mockResolvedValue(false)
    vi.mocked(opaService.canGrant).mockResolvedValue(false)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result).toMatchObject({
      ok: false,
      status: 422,
      body: { error: 'privilege_escalation_blocked', blockingGroup: 'cross-service-grp', operation: 'remove' },
    })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
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
