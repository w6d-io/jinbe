import { describe, it, expect, beforeEach, vi } from 'vitest'

// No administrator rewrites the model in their own favour: not a group they sit in, not a role or
// route map of a service one of their groups holds a role in, not the services of their own
// organisation — and nobody short of a super admin hands out `*`.

const store = vi.hoisted(() => ({
  groups: {} as Record<string, Record<string, string[]>>,
  roles: {} as Record<string, Record<string, string[]>>,
}))

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => 'id') } }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn(async () => store.groups),
    getRoles: vi.fn(async (service: string) => store.roles[service] ?? null),
  },
}))

import { assertMayAssignGroup, assertNoSelfEscalation, grantsEverything } from '../../../services/rbac-escalation-guard.js'
import { opaWorld, resetOpaWorld } from '../../helpers/opa-authz-mock.js'
import { auditEventService } from '../../../services/audit-event.service.js'

const ADMIN = { id: 'id-admin', email: 'admin@example.com' }
const ROOT = { id: 'id-root', email: 'root@example.com' }
const ORG = '11111111-1111-4111-8111-111111111111'

const status = async (p: Promise<unknown>) => {
  try { await p; return 200 } catch (e) { return (e as { statusCode?: number }).statusCode ?? 500 }
}

beforeEach(() => {
  vi.clearAllMocks()
  resetOpaWorld()
  store.groups = {
    ops: { jinbe: ['admin'] },
    billing: { billing: ['viewer'] },
    super_admins: { global: ['super_admin'] },
  }
  store.roles = {
    jinbe: { admin: ['admin:read', 'admin:write'], viewer: ['admin:read'], root: ['*'] },
    billing: { viewer: ['invoices:read'] },
    // As seeded (bootstrap/seed-rbac.ts): global.admin resolves to '*', not only global.super_admin.
    global: { super_admin: ['*'], admin: ['*'] },
  }
  opaWorld.groups['admin@example.com'] = ['ops']
  opaWorld.members['admin@example.com'] = [ORG]
  opaWorld.superAdmins.add('root@example.com')
})

describe('groups', () => {
  it('refuses a change to a group the actor is a member of', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'ops', after: { jinbe: ['admin', 'root'] } }, ADMIN))).toBe(403)
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'ops', after: null }, ADMIN))).toBe(403)
    expect(auditEventService.emit).toHaveBeenCalledWith(expect.objectContaining({ result: 'denied', reason: 'self_escalation' }))
  })

  it('allows a change to a group the actor is not in, when it grants no wildcard', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'billing', after: { billing: ['viewer'] } }, ADMIN))).toBe(200)
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'billing', after: null }, ADMIN))).toBe(200)
  })

  it("refuses a group that grants '*' — a role carrying it, or the global super_admin role", async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'new', after: { jinbe: ['root'] } }, ADMIN))).toBe(403)
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'new', after: { global: ['super_admin'] } }, ADMIN))).toBe(403)
  })

  it('lets a super admin do all of it', async () => {
    opaWorld.groups['root@example.com'] = ['super_admins', 'ops']
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'ops', after: { jinbe: ['root'] } }, ROOT))).toBe(200)
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'new', after: { global: ['super_admin'] } }, ROOT))).toBe(200)
  })
})

describe('service roles and route maps', () => {
  it('refuses the roles or routes of a service a group of the actor holds a role in', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'roles', service: 'jinbe', roles: { viewer: ['admin:write'] } }, ADMIN))).toBe(403)
    expect(await status(assertNoSelfEscalation({ kind: 'routes', service: 'jinbe' }, ADMIN))).toBe(403)
  })

  it('allows them for a service none of their groups reaches', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'roles', service: 'billing', roles: { viewer: ['invoices:read', 'invoices:export'] } }, ADMIN))).toBe(200)
    expect(await status(assertNoSelfEscalation({ kind: 'routes', service: 'billing' }, ADMIN))).toBe(200)
  })

  it("refuses a role carrying '*', whatever the service", async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'roles', service: 'billing', roles: { viewer: ['*'] } }, ADMIN))).toBe(403)
  })

  it('lets a super admin change them', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'roles', service: 'jinbe', roles: { viewer: ['*'] } }, ROOT))).toBe(200)
  })
})

describe('org → service map', () => {
  it("refuses a change to the actor's own organisation's services", async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'org_services', organizationId: ORG }, ADMIN))).toBe(403)
  })

  it('allows it for an organisation they do not belong to', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'org_services', organizationId: '22222222-2222-4222-8222-222222222222' }, ADMIN))).toBe(200)
  })
})

describe("the global role definitions ('global.admin' is '*')", () => {
  it("refuses a group granting global.admin — '*' by another name — even one the actor is not in", async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'billing', after: { billing: ['viewer'], global: ['admin'] } }, ADMIN))).toBe(403)
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'new', after: { global: ['admin'] } }, ADMIN))).toBe(403)
  })

  it("refuses redefining a global role to '*', and any global role change by a holder of one", async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'roles', service: 'global', roles: { super_admin: ['*'], admin: ['*'], ops: ['*'] } }, ADMIN))).toBe(403)
    store.groups.ops = { jinbe: ['admin'], global: ['auditor'] }
    expect(await status(assertNoSelfEscalation({ kind: 'roles', service: 'global', roles: { auditor: ['admin:write'] } }, ADMIN))).toBe(403)
  })

  it('lets a super admin grant global.admin', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'group', name: 'new', after: { global: ['admin'] } }, ROOT))).toBe(200)
  })
})

describe('handing out a platform group (PUT /api/admin/users/:email/groups)', () => {
  it("refuses a group that grants '*' — super_admins, or one binding global.admin — to anyone", async () => {
    store.groups.platform_admins = { global: ['admin'] }
    expect(await status(assertMayAssignGroup('super_admins', 'someone@example.com', ADMIN))).toBe(403)
    expect(await status(assertMayAssignGroup('platform_admins', 'someone@example.com', ADMIN))).toBe(403)
  })

  it('refuses adding oneself to any group', async () => {
    expect(await status(assertMayAssignGroup('billing', 'Admin@Example.com', ADMIN))).toBe(403)
  })

  it('allows a group without a wildcard to somebody else', async () => {
    expect(await status(assertMayAssignGroup('billing', 'someone@example.com', ADMIN))).toBe(200)
  })

  it('lets a super admin do both', async () => {
    expect(await status(assertMayAssignGroup('super_admins', 'someone@example.com', ROOT))).toBe(200)
    expect(await status(assertMayAssignGroup('billing', 'root@example.com', ROOT))).toBe(200)
  })

  it('fails closed', async () => {
    expect(await status(assertMayAssignGroup('billing', 'someone@example.com'))).toBe(401)
    opaWorld.down = true
    expect(await status(assertMayAssignGroup('super_admins', 'someone@example.com', ADMIN))).toBe(503)
  })
})

describe('fail closed', () => {
  it('answers 401 without an identified actor', async () => {
    expect(await status(assertNoSelfEscalation({ kind: 'routes', service: 'billing' }))).toBe(401)
    expect(await status(assertNoSelfEscalation({ kind: 'routes', service: 'billing' }, { email: 'admin@example.com' }))).toBe(401)
  })

  it('answers 503 when OPA cannot be asked, super admin included', async () => {
    opaWorld.down = true
    expect(await status(assertNoSelfEscalation({ kind: 'routes', service: 'billing' }, ADMIN))).toBe(503)
    expect(await status(assertNoSelfEscalation({ kind: 'routes', service: 'billing' }, ROOT))).toBe(503)
  })
})

describe('grantsEverything', () => {
  it('reads the wildcard off the role definitions', async () => {
    expect(await grantsEverything({ jinbe: ['viewer'] })).toBe(false)
    expect(await grantsEverything({ jinbe: ['viewer', 'root'] })).toBe(true)
    expect(await grantsEverything({ global: ['super_admin'] })).toBe(true)
    expect(await grantsEverything({ unknown: ['whatever'] })).toBe(false)
  })
})
