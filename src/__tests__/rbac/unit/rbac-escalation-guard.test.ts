import { describe, it, expect, beforeEach, vi } from 'vitest'

// The holding rule: nobody grants what they do not hold — a group definition, a widened role, a group
// assignment, an import — app by app, what a group carries into every org included. A super admin
// passes by holding everything, never by a flag. What code defines is never changed through the API.

const store = vi.hoisted(() => ({
  groups: {} as Record<string, Record<string, string[]>>,
  roles: {} as Record<string, Record<string, string[]>>,
  everyOrg: {} as Record<string, Record<string, string[]>>,
}))

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => 'id') } }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn(async () => store.groups),
    getRoles: vi.fn(async (service: string) => store.roles[service] ?? null),
    getEveryOrg: vi.fn(async (service: string) => store.everyOrg[service] ?? null),
  },
}))

import { assertBundleWithinOwn, assertMayAssignGroup, assertNoSelfEscalation } from '../../../services/rbac-escalation-guard.js'
import { opaWorld, resetOpaWorld } from '../../helpers/opa-authz-mock.js'
import { auditEventService } from '../../../services/audit-event.service.js'
import { everyOrgDefinitions, roleDefinitions, staffGroups } from '../../../policy/roles.js'

const ADMIN = { id: 'id-admin', email: 'admin@example.com' }
const ROOT = { id: 'id-root', email: 'root@example.com' }

const status = async (p: Promise<unknown>) => {
  try { await p; return 200 } catch (e) { return (e as { statusCode?: number }).statusCode ?? 500 }
}
const refusal = async (p: Promise<unknown>) => {
  try { await p; return null } catch (e) { return e as { statusCode?: number; code?: string; refusal?: Record<string, unknown> } }
}

beforeEach(() => {
  vi.clearAllMocks()
  resetOpaWorld()
  store.groups = {
    ...staffGroups(),
    ops: { billing: ['admin'] },
    billing: { billing: ['viewer'] },
  }
  store.roles = {
    jinbe: roleDefinitions(),
    billing: { admin: ['invoices:read', 'invoices:write'], viewer: ['invoices:read'] },
  }
  store.everyOrg = { jinbe: everyOrgDefinitions() }
  opaWorld.groups['admin@example.com'] = ['ops']
  opaWorld.groups['root@example.com'] = ['super_admins']
})

describe('group definitions', () => {
  it('allows a group that grants nothing beyond what the actor holds', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'readers', after: { billing: ['viewer'] } }, ADMIN))).toBe(200)
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'billing', after: null }, ADMIN))).toBe(200)
  })

  it('refuses one granting what the actor does not hold, in that app (grant_exceeds_own), saying what', async () => {
    const e = await refusal(assertNoSelfEscalation({ kind: 'group', name: 'new', after: { jinbe: ['viewer'] } }, ADMIN))
    expect(e).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own' })
    expect(e!.refusal).toMatchObject({ missingByScope: { jinbe: expect.arrayContaining(['sites:read']) } })
    expect(auditEventService.emit).toHaveBeenCalledWith(expect.objectContaining({ result: 'denied', reason: 'grant_exceeds_own' }))
  })

  it('counts what a group carries into every org: holding the platform part is not enough', async () => {
    // A grant-holder holding everything security holds on platform, but no every-org reach.
    store.roles.jinbe = { ...store.roles.jinbe, lead: [...roleDefinitions().security, 'groups:write'] }
    store.groups.leads = { jinbe: ['lead'] }
    opaWorld.groups['lead@example.com'] = ['leads']
    const e = await refusal(assertNoSelfEscalation({ kind: 'group', name: 'incident', after: { jinbe: ['security'] } }, { id: 'id-lead', email: 'lead@example.com' }))
    expect(e).toMatchObject({ code: 'grant_exceeds_own' })
    expect(e!.refusal).toMatchObject({ missingByScope: { 'every_org:jinbe': ['org.audit:read', 'org.keys:read', 'org.members:read'] } })
  })

  it('a super admin passes by holding everything', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'incident', after: { jinbe: ['security'] } }, ROOT))).toBe(200)
  })

  it('a super admin missing ONE permission is refused like anybody else', async () => {
    store.roles.jinbe = { ...store.roles.jinbe, super_admin: roleDefinitions().super_admin.filter((p) => p !== 'recert:delete') }
    const e = await refusal(assertNoSelfEscalation({ kind: 'group', name: 'incident', after: { jinbe: ['security'] } }, ROOT))
    expect(e).toMatchObject({ code: 'grant_exceeds_own' })
    expect(e!.refusal).toMatchObject({ missing: ['recert:delete'] })
  })

  it('the staff groups and super_admins are defined in code: 409 for everybody', async () => {
    for (const g of ['super_admins', 'staff-viewers']) {
      expect(await refusal(assertNoSelfEscalation({ kind: 'group', name: g, after: { jinbe: ['viewer'] } }, ROOT))).toMatchObject({ statusCode: 409, code: 'defined_in_code' })
      expect(await status(assertNoSelfEscalation({ kind: 'group', name: g, after: null }, ROOT))).toBe(409)
    }
  })
})

describe('roles and route maps', () => {
  it('widening a role some group binds needs what it adds', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'roles', service: 'billing', roles: { viewer: ['invoices:read', 'invoices:write'] } }, ADMIN))).toBe(200)
    expect(await status(assertNoSelfEscalation({ kind: 'roles', service: 'billing', roles: { viewer: ['invoices:read', 'payments:write'] } }, ADMIN))).toBe(403)
  })

  it('a role no group binds grants nobody anything yet', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'roles', service: 'billing', roles: { fresh: ['payments:write'] } }, ADMIN))).toBe(200)
  })

  it("the routes of a service the actor holds a role in are not theirs to change", async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'routes', service: 'billing' }, ADMIN))).toBe(403)
    expect(await status(assertNoSelfEscalation({ kind: 'routes', service: 'shop' }, ADMIN))).toBe(200)
  })
})

describe('group assignment', () => {
  it('needs everything the group confers, for anybody', async () => {
    expect(await status(assertMayAssignGroup('billing', ADMIN))).toBe(200)
    expect(await status(assertMayAssignGroup('staff-viewers', ADMIN))).toBe(403)
    expect(await status(assertMayAssignGroup('super_admins', ROOT))).toBe(200)
  })

  it('a group nothing defines is left to the caller (it confers nothing)', async () => {
    expect(await status(assertMayAssignGroup('ghost', ADMIN))).toBe(200)
  })

  it('401 without an identity, 503 when OPA cannot tell', async () => {
    expect(await status(assertMayAssignGroup('billing', { id: null, email: null } as never))).toBe(401)
    opaWorld.down = true
    expect(await status(assertMayAssignGroup('billing', ADMIN))).toBe(503)
  })
})

describe('bundle imports', () => {
  it('a changed group clears the same rule; a staff group is never imported over', async () => {
    expect(await status(assertBundleWithinOwn([{ name: 'billing', after: { billing: ['invoices:read'] } }], ADMIN))).toBe(200)
    expect(await status(assertBundleWithinOwn([{ name: 'billing', after: { billing: ['payments:write'] } }], ADMIN))).toBe(403)
    expect(await status(assertBundleWithinOwn([{ name: 'super_admins', after: {} }], ROOT))).toBe(409)
  })
})
