import { describe, it, expect, beforeEach, vi } from 'vitest'

// Grant only what you hold, with the staff roles as code defines them: a holder of groups:write /
// groups.members:write may create, widen or hand out a group only when what it grants is a subset of
// what they hold, app by app — otherwise a second account they invited would carry the difference.

const store = vi.hoisted(() => ({
  groups: {} as Record<string, Record<string, string[]>>,
  roles: {} as Record<string, Record<string, string[]>>,
  everyOrg: {} as Record<string, Record<string, string[]>>,
}))

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => 'id') } }))
vi.mock('../../../services/redis-client.service.js', () => ({ redisClientService: { isConnected: true } }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn(async () => store.groups),
    getRoles: vi.fn(async (service: string) => store.roles[service] ?? null),
    getEveryOrg: vi.fn(async (service: string) => store.everyOrg[service] ?? null),
  },
}))

import { assertMayAssignGroup, assertNoSelfEscalation } from '../../../services/rbac-escalation-guard.js'
import { exceeding, groupGrants, heldIn } from '../../../services/grant-subset.js'
import { grantedBy, hintFor } from '../../../services/permission-refusal.js'
import { everyOrgDefinitions, roleDefinitions, staffGroups } from '../../../policy/roles.js'
import { opaWorld, resetOpaWorld } from '../../helpers/opa-authz-mock.js'

const SUPPORT = { id: 'id-support', email: 'support@example.com' }
const OPS = { id: 'id-ops', email: 'ops@example.com' }
const SECURITY = { id: 'id-security', email: 'security@example.com' }
const ROOT = { id: 'id-root', email: 'root@example.com' }

type Refusal = { statusCode?: number; code?: string; refusal?: Record<string, unknown> }
const refusal = async (p: Promise<unknown>): Promise<Refusal | null> => p.then(() => null, (e) => e as Refusal)

beforeEach(() => {
  vi.clearAllMocks()
  resetOpaWorld()
  // As the bootstrap writes them: the staff roles under jinbe, one group each.
  store.roles = { jinbe: roleDefinitions(), billing: { reader: ['invoices:read'] } }
  store.everyOrg = { jinbe: everyOrgDefinitions() }
  store.groups = staffGroups()
  opaWorld.groups[SUPPORT.email] = ['staff-support']
  opaWorld.groups[OPS.email] = ['staff-ops']
  opaWorld.groups[SECURITY.email] = ['staff-security']
  opaWorld.groups[ROOT.email] = ['super_admins']
})

describe('resolution, app by app (as rbac.rego)', () => {
  it('reads each role name in its own app only', () => {
    expect(groupGrants({ billing: ['reader'] }, store.roles)).toEqual({ billing: ['invoices:read'] })
    expect(groupGrants({ billing: ['security'] }, store.roles)).toEqual({})
    expect(groupGrants({ jinbe: ['security'] }, store.roles).jinbe).toContain('users:reset_second_factor')
  })

  it('what somebody holds in one app says nothing about another', () => {
    const held = heldIn([{ jinbe: ['viewer'] }, { billing: ['reader'] }], store.roles, ['jinbe', 'billing'])
    expect(held.jinbe).not.toContain('invoices:read')
    expect(held.billing).toEqual(['invoices:read'])
  })

  it('exceeding is an exact difference: no wildcard, no alias', () => {
    expect(exceeding({ jinbe: ['zones:write', 'sites:read'] }, { jinbe: ['sites:read'] })).toEqual({ jinbe: ['zones:write'] })
    expect(exceeding({ jinbe: ['users:read'] }, { jinbe: ['*'] })).toEqual({ jinbe: ['users:read'] })
  })
})

describe('the alt-account escalation (support holds users:create)', () => {
  it('support invites an alt account, then tries to add it to staff-security: refused', async () => {
    const err = await refusal(assertMayAssignGroup('staff-security', SUPPORT))
    expect(err).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own' })
    expect(err?.refusal?.missing).toEqual(expect.arrayContaining(['users:reset_second_factor', 'users:disable']))
    expect(err?.refusal?.missing).not.toContain('users:read')
  })

  it('nor through a look-alike group bound to the security role', async () => {
    store.groups['helpdesk-plus'] = { jinbe: ['security'] }
    expect(await refusal(assertMayAssignGroup('helpdesk-plus', SUPPORT))).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own' })
  })

  it('support may still hand out a group within what they hold, every-org part included', async () => {
    store.groups.desk = { jinbe: ['viewer'] }
    expect(await refusal(assertMayAssignGroup('desk', SUPPORT))).toBeNull()
    expect(await refusal(assertMayAssignGroup('staff-viewers', SUPPORT))).toBeNull()
  })
})

describe('ops with groups:write', () => {
  it('may not create a group carrying users:reset_second_factor', async () => {
    const err = await refusal(assertNoSelfEscalation({ kind: 'group', name: 'incident', after: { jinbe: ['security'] } }, OPS))
    expect(err).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own' })
    expect(err?.refusal).toMatchObject({ missingByScope: expect.objectContaining({ jinbe: expect.arrayContaining(['users:reset_second_factor']) }) })
    // Who could make the change: the narrowest group holding everything missing first.
    expect(err?.refusal?.grantedBy).toEqual(['staff-security', 'super_admins'])
    expect(err?.refusal?.hint).toBe('Ask an administrator to add you to one of: staff-security, super_admins.')
  })

  it('may create a group within what they hold', async () => {
    expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: 'edge-readers', after: { jinbe: ['viewer'] } }, OPS))).toBeNull()
  })
})

describe('the staff groups', () => {
  it('a security member may hand out staff-security: they hold all of it', async () => {
    expect(await refusal(assertMayAssignGroup('staff-security', SECURITY))).toBeNull()
  })

  it('are never redefined through the API, not even by a super admin', async () => {
    expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: 'staff-security', after: { jinbe: ['security', 'ops'] } }, ROOT))).toMatchObject({ statusCode: 409, code: 'defined_in_code' })
  })
})

describe('a super admin', () => {
  it('passes by holding everything', async () => {
    expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: 'incident', after: { jinbe: ['security'] } }, ROOT))).toBeNull()
    expect(await refusal(assertMayAssignGroup('staff-security', ROOT))).toBeNull()
    expect(await refusal(assertMayAssignGroup('super_admins', ROOT))).toBeNull()
  })
})

describe('fails closed', () => {
  it('answers 401 without an identified actor, 503 when OPA cannot be asked', async () => {
    expect((await refusal(assertMayAssignGroup('desk')))?.statusCode).toBe(401)
    opaWorld.down = true
    expect((await refusal(assertMayAssignGroup('staff-viewers', SUPPORT)))?.statusCode).toBe(503)
  })
})

describe('grantedBy', () => {
  it('lists the groups whose roles hold the permission, the narrowest first', async () => {
    expect(await grantedBy(['users:reset_second_factor'])).toEqual(['staff-security', 'super_admins'])
    expect(await grantedBy(['sites:read'])).toEqual(['staff-viewers', 'staff-developers', 'staff-auditors', 'staff-ops', 'staff-support', 'staff-security', 'super_admins'])
  })

  it('answers an empty list, never an error, when the model cannot be read', async () => {
    const { redisRbacRepository } = await import('../../../services/redis-rbac.repository.js')
    vi.mocked(redisRbacRepository.getGroups).mockRejectedValueOnce(new Error('down'))
    expect(await grantedBy(['users:read'])).toEqual([])
    expect(hintFor(null, ['users:read'])).toBe('Ask an administrator for users:read.')
    expect(hintFor([])).toMatch(/super admin/)
  })
})
