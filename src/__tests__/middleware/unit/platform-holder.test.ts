import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// A staff role holding an org-scoped route's permission across the platform passes that route in
// every organisation (staff-rbac-proposal §1 rule c); everybody else is still decided per org.

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../audit/deny.js', () => ({ denyAudit: vi.fn() }))

import { requireOrgAdmin, requireOrgPermission } from '../../../middleware/require-org-permission.js'
import { holdsDeclaredPermissionGlobally } from '../../../middleware/platform-holder.js'
import { opaWorld, resetOpaWorld } from '../../helpers/opa-authz-mock.js'

const request = (email: string, permission?: string) => ({
  method: 'GET',
  url: '/api/organizations/acme/users',
  params: { organizationId: 'acme' },
  routeOptions: { url: '/api/organizations/:organizationId/users', config: permission ? { permission } : {} },
  userContext: { id: `id-${email}`, email, authVia: 'session' },
  log: { warn: vi.fn() },
  headers: {},
}) as unknown as FastifyRequest
function reply() {
  const r = { code: 0, status(c: number) { r.code = c; return r }, send() { return r } }
  return r
}
const run = async (gate: (q: FastifyRequest, p: FastifyReply) => unknown, req: FastifyRequest) => {
  const r = reply()
  await gate(req, r as unknown as FastifyReply)
  return r.code
}

beforeEach(() => {
  resetOpaWorld()
  opaWorld.permissions['sam@x.io'] = ['org.members:read', 'org.members:write']
  opaWorld.permissions['legacy@x.io'] = ['admin:read']
})

describe('holdsDeclaredPermissionGlobally', () => {
  it('reads the route\'s own declaration', async () => {
    expect(await holdsDeclaredPermissionGlobally(request('sam@x.io', 'org.members:read'))).toBe(true)
    expect(await holdsDeclaredPermissionGlobally(request('sam@x.io', 'org.keys:read'))).toBe(false)
    // admin:read is a legacy alias of org.members:read for one release.
    expect(await holdsDeclaredPermissionGlobally(request('legacy@x.io', 'org.members:read'))).toBe(true)
  })

  it('never widens a gate mounted without a declaration', async () => {
    expect(await holdsDeclaredPermissionGlobally(request('sam@x.io'))).toBe(false)
  })
})

describe('the org gates', () => {
  it('requireOrgPermission (declared) admits the platform holder in any org, refuses the rest', async () => {
    expect(await run(requireOrgPermission(), request('sam@x.io', 'org.members:read'))).toBe(0)
    expect(await run(requireOrgPermission(), request('nobody@x.io', 'org.members:read'))).toBe(403)
  })

  it('requireOrgAdmin admits the platform holder too; the roster admin still passes', async () => {
    expect(await run(requireOrgAdmin(), request('sam@x.io', 'org.members:write'))).toBe(0)
    opaWorld.manageable['olga@x.io'] = ['acme']
    expect(await run(requireOrgAdmin(), request('olga@x.io', 'org.members:write'))).toBe(0)
    expect(await run(requireOrgAdmin(), request('nobody@x.io', 'org.members:write'))).toBe(403)
  })

  it('OPA down is a 503, never an allow', async () => {
    opaWorld.down = true
    expect(await run(requireOrgPermission(), request('sam@x.io', 'org.members:read'))).toBe(503)
  })
})
