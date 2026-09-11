import { describe, it, expect, beforeEach, vi } from 'vitest'

// The Redis mutex is infrastructure; these units validate the gate logic, not
// locking (the lock has its own test). Passthrough so no Redis is required.
// The store the engine actually reads. Group changes land here, so a test that left it real
// would reach for Postgres.
// The model the gates read. See the helper for why they read a model rather than predicates.
vi.mock('../../../services/authorization-model.service.js', async () =>
  (await import('../../helpers/authorization-model-mock.js')).authorizationModelMock())

vi.mock('../../../services/organisation-store.js', () => ({
  addToGroup: vi.fn().mockResolvedValue(undefined),
  applyGroupChange: vi.fn().mockResolvedValue(undefined),
  removeFromGroup: vi.fn().mockResolvedValue(undefined),
  groupsForSubjects: vi.fn().mockResolvedValue(new Map()),
  organisationStoreConfigured: vi.fn().mockReturnValue(true),
}))

vi.mock('../../../services/redis-lock.js', () => ({
  withRedisLock: (_name: string, fn: () => unknown) => fn(),
}))

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getUserGroups: vi.fn().mockResolvedValue([]),
    updateUserGroups: vi.fn().mockResolvedValue(undefined),
    // Default: the target has a second factor, so cases not about MFA reach their own gate.
    hasMFA: vi.fn().mockResolvedValue(true),
  },
}))

vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: {
    // Default: the group under test is NOT global (a plain "admins" group), so
    // the wildcard_in_org path keeps its org-"*" behaviour. Cases exercising a
    // global group override this per-test.
    assertSuperAdmin: vi.fn().mockResolvedValue(undefined),
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
import { applyGroupChange, groupsForSubjects } from '../../../services/organisation-store.js'
import { auditEventService } from '../../../services/audit-event.service.js'
import {
  AuthorizationModelUnavailableError,
  groupFacts,
} from '../../../services/authorization-model.service.js'
import {
  authorizationModel,
  resetAuthorizationModel,
} from '../../helpers/authorization-model-mock.js'

/** What one call to the atomic write took away, and what it gave. */
const revokedIn = (call: unknown[]) => call[1] as string[]
const grantedIn = (call: unknown[]) => call[2] as string[]
const allRevoked = () => vi.mocked(applyGroupChange).mock.calls.flatMap(revokedIn)
const allGranted = () => vi.mocked(applyGroupChange).mock.calls.flatMap(grantedIn)

/** Seed what the ENFORCED store says this identity holds — the pre-image the diff is taken against. */
function holds(...groups: string[]) {
  vi.mocked(groupsForSubjects).mockResolvedValue(new Map([['user-123', groups]]))
}

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
    holds()
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

  it('takes the last group away instead of putting the base one back', async () => {
    // Asking for none used to write `users`, which came from the retired model. Here that group is
    // not declared and confers nothing, so forcing it wrote a row granting nothing and made "holds
    // no group" unreachable — the removal returned 200 and left the person where they were.
    holds('platform-operator')

    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: [],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', [])
    expect(allRevoked()).toContain('platform-operator')
    expect(allGranted()).toEqual([])
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
    holds('users')

    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(rbacService.assertSuperAdmin).not.toHaveBeenCalled()
    expect(kratosService.hasMFA).not.toHaveBeenCalled()
    expect(kratosService.updateUserGroups).toHaveBeenCalled()
  })
})

describe('userGroupsService.applyGroupUpdate — MFA step-up (R2)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    holds()
    vi.mocked(rbacService.assertSuperAdmin).mockResolvedValue(undefined)
  })

  const assignPrivileged = (actor: Record<string, unknown>) =>
    userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['super_admins'],
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
    expect(kratosService.updateUserGroups).toHaveBeenCalledWith('target@example.com', ['super_admins'])
  })

  it('does NOT require step-up for a non-privileged change (demotion to base group)', async () => {
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
    holds()
    // The flag group is EMPTY → NOT admin-power. Without the explicit guard the
    // global path (isAdminPowerGroup) would skip the super_admin check for it.
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

  it('org-scoped path: a group that grants nothing is still not waved through', async () => {
    // The property worth keeping from when this went to a delegation policy: the org-scoped
    // exemption keys on the base group NAME ("users"), so a group that merely resolves to no
    // permission is NOT exempt. It is refused with the whole path, which is stricter than the
    // per-group check it replaces.

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['org_admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.body).toMatchObject({ error: 'delegation_not_defined', blockingGroup: 'org_admins' })
    }
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })
})

describe('userGroupsService.applyGroupUpdate — super_admin_required policy', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    holds()
  })

  it('returns 422 privilege_escalation_blocked when assertSuperAdmin throws 403', async () => {
    vi.mocked(rbacService.assertSuperAdmin).mockRejectedValueOnce(
      Object.assign(new Error('Only super_admins may assign group ...'), { statusCode: 403 })
    )

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['super_admins'],
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
        blockingGroup: 'super_admins',
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
      newGroups: ['super_admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.status).toBe(401)
  })

  it('proceeds to MFA gate when actor IS super_admin', async () => {
    vi.mocked(rbacService.assertSuperAdmin).mockResolvedValueOnce(undefined)
    vi.mocked(kratosService.hasMFA).mockResolvedValue(false)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['super_admins'],
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
        targetGroups: ['super_admins'],
      }),
    })
  })

  it('does NOT gate REMOVALS on the super_admin endpoint (a super_admin may freely remove)', async () => {
    // A super_admin drops a privileged group. Removals are not gated here — the
    // endpoint is super_admin-gated at the route and a super_admin can remove
    // anything. Only *added* admin-power groups reach assertSuperAdmin.
    holds('admins', 'users')

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

describe('userGroupsService.applyGroupUpdate — the store the engine reads', () => {
  // Until today the console wrote group changes to Kratos metadata only, while the artefact the
  // engine decides against carries `group_members` from the database. Nothing joined the two, so a
  // change made on screen was never enforced.
  beforeEach(() => {
    vi.clearAllMocks()
    holds()
  })

  it('writes a grant where the engine reads it, keyed on the identity', async () => {
    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users', 'operators'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(true)
    // The identity, not the address: an address changes hands, a membership pointing at one would
    // follow whoever holds it next.
    expect(allGranted()).toContain('operators')
  })

  it('takes a revocation away BEFORE the display forgets it', async () => {
    // The order is a safety property. Removing from the display and then failing to remove where it
    // counts leaves a right that is still enforced and no longer visible — the failure nobody would
    // notice. So revocations go to the enforced store first.
    holds('users', 'operators')
    const order: string[] = []
    vi.mocked(applyGroupChange).mockImplementation(async (_id, revoked) => {
      if (revoked.length > 0) order.push('store')
    })
    vi.mocked(kratosService.updateUserGroups).mockImplementation(async () => {
      order.push('kratos')
    })

    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(allRevoked()).toContain('operators')
    expect(order).toEqual(['store', 'kratos'])
  })

  it('grants only AFTER the display shows it, so nothing is enforced invisibly', async () => {
    const order: string[] = []
    vi.mocked(applyGroupChange).mockImplementation(async (_id, _revoked, granted) => {
      if (granted.length > 0) order.push('store')
    })
    vi.mocked(kratosService.updateUserGroups).mockImplementation(async () => {
      order.push('kratos')
    })

    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users', 'operators'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    // The invariant rather than the count: how many groups are new is beside the point, no grant may
    // reach the enforced store before the display has it.
    expect(order[0]).toBe('kratos')
    expect(order.slice(1).every((step) => step === 'store')).toBe(true)
  })

  it('touches neither store for a group that did not change', async () => {
    // `group_members` is keyed on (subject, group), so rewriting an unchanged row would lose
    // `created_by` and `created_at` — the two columns that answer "who granted this, and when".
    holds('users', 'operators')

    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users', 'operators'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(allGranted()).toEqual([])
    expect(allRevoked()).toEqual([])
  })
})

describe('userGroupsService.applyGroupUpdate — the org-scoped path has no delegation to check', () => {
  // What this block used to assert: an OPA delegation policy (`can_grant`) decided whether an
  // org-scoped admin could hand out a given group inside their organisation, with containment,
  // service-scope and authority tiers. None of that survives in `strada.authz` — no permission
  // expresses "may hand out this group here", so there is nothing to check against.
  //
  // It is refused with a reason that says so, rather than through a query that answers nothing:
  // that query was reaching an engine which stopped serving `data.rbac.*` when the model changed,
  // and every assignment had been refused since — a 403 indistinguishable from a missing right.
  beforeEach(() => {
    vi.clearAllMocks()
    holds()
  })

  it('refuses an org-scoped grant, and names what is missing', async () => {
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
      body: expect.objectContaining({ error: 'delegation_not_defined' }),
    })
  })

  it('refuses an org-scoped REMOVAL too, so nothing is stripped through a path with no authority', async () => {
    // The property the old block guarded and which must survive its removal: a replace-PUT through
    // the org endpoint must not be able to take a group away either. Refusing the whole path is a
    // stronger guarantee than checking each group, not a weaker one.
    holds('admins')

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: [],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(result).toMatchObject({ ok: false, status: 422 })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
    expect(allRevoked()).toEqual([])
  })

  it('writes nothing at all when it refuses', async () => {
    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
      auditEventType: 'organization_user.groups_changed',
    })

    expect(allGranted()).toEqual([])
    expect(allRevoked()).toEqual([])
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
  })
})

describe('userGroupsService.applyGroupUpdate — MFA gate', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    holds()
  })

  it('returns 422 mfa_required when the target of a platform grant has no second factor', async () => {
    vi.mocked(kratosService.hasMFA).mockResolvedValue(false)

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

describe('applyGroupUpdate — denied writes emit an audit event (A2)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    holds()
  })

  it('emits a denied event when a privilege escalation is blocked', async () => {
    // A non-super actor attempts to grant an admin-power group on the global
    // endpoint → assertSuperAdmin rejects → privilege_escalation_blocked.
    vi.mocked(rbacService.assertSuperAdmin).mockRejectedValue(
      Object.assign(new Error('not a super_admin'), { statusCode: 403 }),
    )

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['super_admins'],
      actor: { email: 'attacker@x.io', ip: '9.9.9.9', aal: 'aal2', authenticatedAt: new Date() },
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(false)
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
    expect(auditEventService.emit).toHaveBeenCalledWith(
      expect.objectContaining({
        category: 'access',
        result: 'denied',
        reason: 'privilege_escalation_blocked',
        target: 'user:target@example.com',
        targetType: 'user',
      }),
    )
  })
})

describe('userGroupsService.applyGroupUpdate — the model the engine decides against', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetAuthorizationModel()
    holds()
    vi.mocked(kratosService.hasMFA).mockResolvedValue(true)
    vi.mocked(rbacService.assertSuperAdmin).mockResolvedValue(undefined)
  })

  it('gates a group the model declares but the retired catalogue never held', async () => {
    // The defect this closes. `platform-admin` grants the whole administration API in every
    // organisation, and the predicates that used to decide whether handing it out needed the
    // actor's authority and the target's second factor asked a store that had never heard of it —
    // so all of them answered "not needed", silently, for the most powerful group there is.
    authorizationModel.groups['platform-admin'] = { '*': ['platform-admin'] }
    vi.mocked(rbacService.assertSuperAdmin).mockRejectedValueOnce(
      Object.assign(new Error('not a platform admin'), { statusCode: 403 }),
    )

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['platform-admin'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result).toMatchObject({ ok: false, status: 422 })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
    expect(allGranted()).toEqual([])
  })

  it('requires the target of that grant to hold a second factor', async () => {
    authorizationModel.groups['platform-admin'] = { '*': ['platform-admin'] }
    vi.mocked(kratosService.hasMFA).mockResolvedValue(false)

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['platform-admin'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result).toMatchObject({ ok: false, status: 422, body: { error: 'mfa_required' } })
    expect(allGranted()).toEqual([])
  })

  it('does NOT gate a grant scoped to one organisation', async () => {
    // Scope is what separates a platform grant from a tenant one, now that the model has no `*`
    // permission to spot. A role held in a single organisation is an ordinary tenant role.
    authorizationModel.groups['premium-operator'] = { 'org-9': ['operator'] }

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['premium-operator'],
      actor: { email: 'a@x.io', ip: '1', aal: 'aal1', authenticatedAt: new Date() },
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(true)
    expect(rbacService.assertSuperAdmin).not.toHaveBeenCalled()
  })

  it('refuses a group the model does not declare, and writes nothing', async () => {
    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['kuma-admin'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result).toMatchObject({
      ok: false,
      status: 400,
      body: { message: expect.stringContaining('Not in the authorization model: kuma-admin') },
    })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
    expect(allGranted()).toEqual([])
  })

  it('still lets an undeclared group be REMOVED, so a legacy one can be cleaned up', async () => {
    // Only additions are checked. A group predating the model confers nothing, and refusing to take
    // it away would leave the rows nobody can explain exactly where they are.
    holds('kuma-admin', 'users')

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(true)
    expect(allRevoked()).toContain('kuma-admin')
  })

  it('refuses with 503 when the model cannot be read, rather than deciding without it', async () => {
    // "Confers nothing" and "I could not tell what it confers" are opposite facts. Reading the
    // second as the first is how a grant slips past every gate at once.
    vi.mocked(groupFacts).mockRejectedValueOnce(
      new AuthorizationModelUnavailableError('ConfigMaps unreachable'),
    )

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['super_admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result).toMatchObject({ ok: false, status: 503 })
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
    expect(allGranted()).toEqual([])
  })
})

describe('userGroupsService.applyGroupUpdate — a membership the display copy never had', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetAuthorizationModel()
    vi.mocked(kratosService.hasMFA).mockResolvedValue(true)
    vi.mocked(rbacService.assertSuperAdmin).mockResolvedValue(undefined)
  })

  it('revokes it, even though Kratos never mentioned it', async () => {
    // Measured on a real account: `group_members` held `platform-operator`, Kratos metadata held
    // `users`. Taken against the metadata, the diff never saw the group — so it was never in
    // `removed`, never revoked, and the screen reported a removal that did not happen.
    holds('platform-operator')
    vi.mocked(kratosService.getUserGroups).mockResolvedValue(['users'])

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(true)
    expect(allRevoked()).toContain('platform-operator')
  })

  it('does not re-grant what the display copy is merely missing', async () => {
    // The mirror: a group the enforced store already holds is not an ADDITION, so it must not be put
    // through the gates again — nor written twice, which would lose who granted it and when.
    holds('super_admins')
    vi.mocked(kratosService.getUserGroups).mockResolvedValue([])

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['super_admins'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result.ok).toBe(true)
    expect(allGranted()).toEqual([])
    expect(rbacService.assertSuperAdmin).not.toHaveBeenCalled()
  })

  it('reports the enforced pre-image in the audit trail, not the copy', async () => {
    holds('platform-operator')
    vi.mocked(kratosService.getUserGroups).mockResolvedValue(['users'])

    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    const emitted = vi.mocked(auditEventService.emit).mock.calls.map(([event]) => event)
    const change = emitted.find((event) => event.type === 'user.groups_changed')
    expect(change?.details).toMatchObject({ oldGroups: ['platform-operator'] })
  })
})

describe('userGroupsService.applyGroupUpdate — a change lands whole or not at all', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetAuthorizationModel()
    vi.mocked(kratosService.hasMFA).mockResolvedValue(true)
    vi.mocked(rbacService.assertSuperAdmin).mockResolvedValue(undefined)
  })

  it('hands every revocation to one call, and every grant to one call', async () => {
    // Applied a statement at a time, a failure halfway leaves somebody holding part of what was
    // asked and part of what was not — a state no gate decided and nothing records.
    holds('admins', 'devs')

    await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['viewers', 'operators'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    const calls = vi.mocked(applyGroupChange).mock.calls
    expect(calls).toHaveLength(2)
    expect(revokedIn(calls[0]).sort()).toEqual(['admins', 'devs'])
    expect(grantedIn(calls[0])).toEqual([])
    expect(revokedIn(calls[1])).toEqual([])
    expect(grantedIn(calls[1]).sort()).toEqual(['operators', 'viewers'])
  })

  it('refuses without touching either store when a gate says no', async () => {
    // The five-group change measured in dev: refused on the actor's step-up, and the screen then
    // showed the PREVIOUS state — which reads as "three of five failed" unless the refusal says it
    // applied nothing.
    authorizationModel.groups['platform-admin'] = { '*': ['platform-admin'] }
    holds('premium-operator')

    const result = await userGroupsService.applyGroupUpdate({
      identity: IDENTITY,
      newGroups: ['platform-admin', 'premium-operator'],
      actor: { email: 'a@x.io', ip: '1', aal: 'aal1', authenticatedAt: new Date() },
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })

    expect(result).toMatchObject({ ok: false, body: { error: 'reauth_required' } })
    expect(applyGroupChange).not.toHaveBeenCalled()
    expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
    // And it says so, rather than leaving the caller to infer it from a screen that did not change.
    if (!result.ok) expect(result.body).toMatchObject({ applied: false })
  })
})
