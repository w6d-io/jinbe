import { describe, it, expect, beforeEach, vi } from 'vitest'

// The holding rule has one copy, the policy's rbac.delegation verdicts: jinbe asks it for every grant
// and renders the answer. What the rule decides is proven against the policy in opal-policies
// (contract_test.rego over policy-contract.json); here, what jinbe asks and what it does with a verdict.
// What code defines is never changed through the API (409), and nothing fails open.

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

import { assertBundleWithinOwn, assertMayAssignGroup, assertMayRemoveFromGroups, assertNoSelfEscalation, verdictRefusal } from '../../../services/rbac-escalation-guard.js'
import { opaWorld, refused, resetOpaWorld } from '../../helpers/opa-authz-mock.js'
import { auditEventService } from '../../../services/audit-event.service.js'
import { grantVerdict } from '../../../authz/opa.js'
import { staffGroups } from '../../../policy/roles.js'

const ADMIN = { id: 'id-admin', email: 'admin@example.com' }

type Refusal = { statusCode?: number; code?: string; message?: string; refusal?: Record<string, unknown> }
const refusal = async (p: Promise<unknown>): Promise<Refusal | null> => p.then(() => null, (e) => e as Refusal)

beforeEach(() => {
  vi.clearAllMocks()
  resetOpaWorld()
  store.groups = { ...staffGroups(), billing: { billing: ['viewer'] } }
  store.roles = { billing: { admin: ['invoices:read', 'invoices:write'], viewer: ['invoices:read'] } }
  opaWorld.groups[ADMIN.email] = ['billing']
  opaWorld.permissions[ADMIN.email] = ['invoices:read']
})

describe('what jinbe asks the policy', () => {
  it('a group definition: define_group with the group as it will be', async () => {
    await assertNoSelfEscalation({ kind: 'group', name: 'readers', after: { billing: ['viewer'] } }, ADMIN)
    expect(grantVerdict).toHaveBeenCalledWith({ kind: 'define_group', actor: ADMIN.email, definition: { billing: ['viewer'] } })
  })

  it('handing out a group: add_to_group; taking groups away: remove_from_group, once', async () => {
    await assertMayAssignGroup('staff-viewers', ADMIN)
    await assertMayRemoveFromGroups(['billing', 'staff-viewers'], ADMIN)
    await assertMayRemoveFromGroups([], ADMIN)
    expect(vi.mocked(grantVerdict).mock.calls.map(([q]) => q)).toEqual([
      { kind: 'add_to_group', actor: ADMIN.email, group: 'staff-viewers' },
      { kind: 'remove_from_group', actor: ADMIN.email },
    ])
  })

  it('deleting a group takes power away: nothing beyond the route is asked', async () => {
    expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: 'billing', after: null }, ADMIN))).toBeNull()
    expect(grantVerdict).not.toHaveBeenCalled()
  })
})

describe('a refused verdict', () => {
  it('answers 403 grant_exceeds_own with what is missing, the every-org part named, who covers it, audited', async () => {
    opaWorld.verdict = () => refused({
      reasons: ['missing_every_org_permissions', 'missing_permissions'],
      missing: { jinbe: ['users:reset_second_factor'] },
      missingEveryOrg: { jinbe: ['org.members:write'] },
      grantedBy: ['staff-security', 'super_admins'],
    })
    const e = await refusal(assertMayAssignGroup('staff-security', ADMIN))
    expect(e).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own' })
    expect(e!.refusal).toMatchObject({
      missing: ['users:reset_second_factor', 'every organisation: org.members:write'],
      missingByScope: { jinbe: ['users:reset_second_factor'], 'every_org:jinbe': ['org.members:write'] },
      reasons: ['missing_every_org_permissions', 'missing_permissions'],
      grantedBy: ['staff-security', 'super_admins'],
      hint: 'Ask an administrator to add you to one of: staff-security, super_admins.',
    })
    expect(e!.message).toContain('every organisation: org.members:write')
    expect(auditEventService.emit).toHaveBeenCalledWith(expect.objectContaining({ result: 'denied', reason: 'grant_exceeds_own' }))
  })

  it('names the one permission missing as `permission`', () => {
    expect(verdictRefusal(refused({ missing: { jinbe: ['groups:write'] } }))).toMatchObject({ permission: 'groups:write', missing: ['groups:write'] })
  })

  it('a refusal with nothing missing still refuses and says why', async () => {
    opaWorld.verdict = () => refused({ reasons: ['invalid_definition'], grantedBy: [] })
    const e = await refusal(assertNoSelfEscalation({ kind: 'group', name: 'odd', after: { billing: ['viewer'] } }, ADMIN))
    expect(e).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own' })
    expect(e!.message).toContain('invalid_definition')
  })
})

describe('defined in code', () => {
  it('the staff groups and super_admins: 409 for everybody, before the policy is asked', async () => {
    for (const g of ['super_admins', 'staff-viewers']) {
      expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: g, after: { jinbe: ['viewer'] } }, ADMIN))).toMatchObject({ statusCode: 409, code: 'defined_in_code' })
      expect(await refusal(assertBundleWithinOwn([{ name: g, after: {} }], ADMIN))).toMatchObject({ statusCode: 409 })
    }
    expect(grantVerdict).not.toHaveBeenCalled()
  })
})

describe('what the policy cannot see yet: a widened role, an imported bundle', () => {
  it('widening a role some group binds needs what it adds, as OPA resolves the actor', async () => {
    expect(await refusal(assertNoSelfEscalation({ kind: 'roles', service: 'billing', roles: { viewer: ['invoices:read'] } }, ADMIN))).toBeNull()
    const e = await refusal(assertNoSelfEscalation({ kind: 'roles', service: 'billing', roles: { viewer: ['invoices:read', 'payments:write'] } }, ADMIN))
    expect(e).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own', refusal: { missing: ['payments:write'] } })
    // A role no group binds grants nobody anything yet.
    expect(await refusal(assertNoSelfEscalation({ kind: 'roles', service: 'billing', roles: { fresh: ['payments:write'] } }, ADMIN))).toBeNull()
  })

  it('an imported group changing what it grants clears the same subset test', async () => {
    expect(await refusal(assertBundleWithinOwn([{ name: 'billing', after: { billing: ['invoices:read'] } }], ADMIN))).toBeNull()
    expect((await refusal(assertBundleWithinOwn([{ name: 'billing', after: { billing: ['payments:write'] } }], ADMIN)))?.statusCode).toBe(403)
  })

  it("the routes of a service the actor holds a role in are not theirs to change", async () => {
    expect((await refusal(assertNoSelfEscalation({ kind: 'routes', service: 'billing' }, ADMIN)))?.statusCode).toBe(403)
    expect(await refusal(assertNoSelfEscalation({ kind: 'routes', service: 'shop' }, ADMIN))).toBeNull()
  })
})

describe('fails closed', () => {
  it('401 without an identity; 503 when OPA cannot tell — never an allow', async () => {
    expect((await refusal(assertMayAssignGroup('billing', { id: null, email: null } as never)))?.statusCode).toBe(401)
    opaWorld.down = true
    expect((await refusal(assertMayAssignGroup('billing', ADMIN)))?.statusCode).toBe(503)
    expect((await refusal(assertMayRemoveFromGroups(['billing'], ADMIN)))?.statusCode).toBe(503)
    expect((await refusal(assertNoSelfEscalation({ kind: 'group', name: 'x', after: { billing: ['viewer'] } }, ADMIN)))?.statusCode).toBe(503)
    expect((await refusal(assertBundleWithinOwn([{ name: 'billing', after: { billing: ['invoices:read'] } }], ADMIN)))?.statusCode).toBe(503)
  })
})
