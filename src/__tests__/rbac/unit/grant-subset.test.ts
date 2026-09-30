import { describe, it, expect, beforeEach, vi } from 'vitest'

// Grant only what you hold. A holder of groups:write / groups.members:write short of a super admin
// may create, widen or hand out a group only when what it grants is a subset of what they hold, scope
// by scope — otherwise a second account they invited would carry the difference. The staff groups and
// super_admins are a super admin's alone.

const store = vi.hoisted(() => ({
  groups: {} as Record<string, Record<string, string[]>>,
  roles: {} as Record<string, Record<string, string[]>>,
}))

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => 'id') } }))
vi.mock('../../../services/redis-client.service.js', () => ({ redisClientService: { isConnected: true } }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn(async () => store.groups),
    getRoles: vi.fn(async (service: string) => store.roles[service] ?? null),
  },
}))

import { assertGrantWithinOwn, assertMayAssignGroup, assertNoSelfEscalation } from '../../../services/rbac-escalation-guard.js'
import { covers, exceeding, groupGrants, heldIn, STAFF_GROUPS } from '../../../services/grant-subset.js'
import { grantedBy, hintFor } from '../../../services/permission-refusal.js'
import { globalRoleDefinitions, ROLES, STAFF_ROLES } from '../../../policy/roles.js'
import { opaWorld, resetOpaWorld } from '../../helpers/opa-authz-mock.js'

const SUPPORT = { id: 'id-support', email: 'support@example.com' }
const OPS = { id: 'id-ops', email: 'ops@example.com' }
const SECURITY = { id: 'id-security', email: 'security@example.com' }
const ROOT = { id: 'id-root', email: 'root@example.com' }
const ALT = 'alt@example.com'

type Refusal = { statusCode?: number; code?: string; refusal?: Record<string, unknown> }
const refusal = async (p: Promise<unknown>): Promise<Refusal | null> => p.then(() => null, (e) => e as Refusal)

beforeEach(() => {
  vi.clearAllMocks()
  resetOpaWorld()
  // As the bootstrap seeds them (seed-staff.ts): each staff role in roles.global, one group each.
  store.roles = { global: globalRoleDefinitions(), jinbe: { security: ['sites:read'], viewer: ['sites:read'] } }
  store.groups = Object.fromEntries(STAFF_ROLES.map((r) => [ROLES[r].group, { global: [r] }]))
  opaWorld.groups[SUPPORT.email] = ['staff-support']
  opaWorld.groups[OPS.email] = ['staff-ops']
  opaWorld.groups[SECURITY.email] = ['staff-security']
  opaWorld.superAdmins.add(ROOT.email)
})

describe('resolution, scope by scope (as rbac.rego)', () => {
  it('reads global names in roles.global and app names in that app, never across', () => {
    // jinbe.security is a different role from global.security: binding one never grants the other.
    expect(groupGrants({ jinbe: ['security'] }, store.roles)).toEqual({ jinbe: ['sites:read'] })
    expect(groupGrants({ global: ['security'] }, store.roles).global).toContain('users:reset_second_factor')
  })

  it('what somebody holds in an app includes their global permissions; globally only the global ones', () => {
    const held = heldIn([{ global: ['viewer'] }, { billing: ['reader'] }], { ...store.roles, billing: { reader: ['invoices:read'] } }, ['global', 'billing'])
    expect(held.global).not.toContain('invoices:read')
    expect(held.billing).toEqual(expect.arrayContaining(['invoices:read', 'sites:read']))
  })

  it("a legacy alias is covered by holding everything it stands for, and '*' covers everything", () => {
    expect(covers(['groups.members:write', 'groups.members:revoke'], 'users:assign_group')).toBe(true)
    expect(covers(['groups.members:write'], 'users:assign_group')).toBe(false)
    expect(covers(['*'], 'users:reset_second_factor')).toBe(true)
    expect(exceeding({ global: ['zones:write', 'sites:read'] }, { global: ['sites:read'] })).toEqual({ global: ['zones:write'] })
  })
})

describe('the alt-account escalation (support holds users:create)', () => {
  it('support invites an alt account, then tries to add it to staff-security: refused', async () => {
    const err = await refusal(assertMayAssignGroup('staff-security', ALT, SUPPORT))
    expect(err).toMatchObject({ statusCode: 403, code: 'staff_group_super_admin_only' })
    expect(err?.refusal).toMatchObject({ code: 'staff_group_super_admin_only', permission: '*', grantedBy: ['super_admins'] })
  })

  it('nor through a look-alike group bound to the security role', async () => {
    store.groups['helpdesk-plus'] = { global: ['security'] }
    const err = await refusal(assertMayAssignGroup('helpdesk-plus', ALT, SUPPORT))
    expect(err).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own' })
    expect(err?.refusal?.missing).toEqual(expect.arrayContaining(['users:reset_second_factor', 'users:disable']))
    expect(err?.refusal?.missing).not.toContain('users:read')
  })

  it('support may still hand out a group within what they hold', async () => {
    store.groups.desk = { global: ['viewer'] }
    expect(await refusal(assertMayAssignGroup('desk', ALT, SUPPORT))).toBeNull()
  })
})

describe('ops with groups:write', () => {
  it('may not create a group carrying users:reset_second_factor', async () => {
    const err = await refusal(assertNoSelfEscalation({ kind: 'group', name: 'incident', after: { global: ['security'] } }, OPS))
    expect(err).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own' })
    expect(err?.refusal).toMatchObject({ missingByScope: { global: expect.arrayContaining(['users:reset_second_factor']) } })
    // Who could make the change: a group holding everything missing, the wildcard last.
    expect(err?.refusal?.grantedBy).toEqual(['staff-security', 'super_admins'])
    expect(err?.refusal?.hint).toBe('Ask an administrator to add you to one of: staff-security, super_admins.')
  })

  it('nor through a custom global role, nor by widening a staff group they are not in', async () => {
    store.roles.global.resetter = ['users:reset_second_factor']
    expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: 'resetters', after: { global: ['resetter'] } }, OPS))).toMatchObject({ code: 'grant_exceeds_own' })
    expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: 'staff-viewers', after: { global: ['viewer', 'ops'] } }, OPS))).toMatchObject({ code: 'staff_group_super_admin_only' })
  })

  it('may create a group within what they hold', async () => {
    expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: 'edge-readers', after: { global: ['viewer'] } }, OPS))).toBeNull()
  })
})

describe('staff groups are a super admin\'s alone', () => {
  it('covers every staff group and super_admins', () => {
    expect([...STAFF_GROUPS].sort()).toEqual(['staff-auditors', 'staff-developers', 'staff-ops', 'staff-security', 'staff-support', 'staff-viewers', 'super_admins'])
  })

  it('refuses a security member handing out staff-security, though they hold all of it', async () => {
    expect(await refusal(assertMayAssignGroup('staff-security', ALT, SECURITY))).toMatchObject({ statusCode: 403, code: 'staff_group_super_admin_only' })
    expect(await refusal(assertGrantWithinOwn('staff-security', SECURITY))).toMatchObject({ code: 'staff_group_super_admin_only' })
  })
})

describe('a super admin', () => {
  it('still may do all of it', async () => {
    expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: 'incident', after: { global: ['security'] } }, ROOT))).toBeNull()
    expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: 'staff-security', after: { global: ['security', 'ops'] } }, ROOT))).toBeNull()
    expect(await refusal(assertMayAssignGroup('staff-security', ALT, ROOT))).toBeNull()
    expect(await refusal(assertGrantWithinOwn('staff-security', ROOT))).toBeNull()
  })
})

describe('fails closed', () => {
  it('answers 401 without an identified actor, 503 when OPA cannot be asked', async () => {
    expect((await refusal(assertGrantWithinOwn('desk')))?.statusCode).toBe(401)
    opaWorld.down = true
    expect((await refusal(assertGrantWithinOwn('staff-viewers', SUPPORT)))?.statusCode).toBe(503)
    expect((await refusal(assertMayAssignGroup('staff-viewers', ALT, SUPPORT)))?.statusCode).toBe(503)
  })
})

describe('grantedBy', () => {
  it('lists the groups whose roles hold the permission, staff included, the wildcard last', async () => {
    expect(await grantedBy(['users:reset_second_factor'])).toEqual(['staff-security', 'super_admins'])
    expect(await grantedBy(['sites:read'])).toEqual(['staff-auditors', 'staff-developers', 'staff-ops', 'staff-security', 'staff-support', 'staff-viewers', 'super_admins'])
  })

  it('answers an empty list, never an error, when the model cannot be read', async () => {
    const { redisRbacRepository } = await import('../../../services/redis-rbac.repository.js')
    vi.mocked(redisRbacRepository.getGroups).mockRejectedValueOnce(new Error('down'))
    expect(await grantedBy(['users:read'])).toEqual([])
    expect(hintFor(null, ['users:read'])).toBe('Ask an administrator for users:read.')
    expect(hintFor([])).toMatch(/super admin/)
  })
})
