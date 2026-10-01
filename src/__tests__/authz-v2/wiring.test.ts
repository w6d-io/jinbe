import { describe, it, expect, vi, afterEach } from 'vitest'

const queryOpa = vi.fn(async (rule: string) => (rule === 'rbac/super_admin' ? true : { groups: ['staff-support'], roles: ['support'], permissions: ['orgs.members:write', 'users:read'] }))
vi.mock('../../services/opa-client.js', () => ({ queryOpa }))

const { isSuperAdmin, clearAuthzCache } = await import('../../authz/opa.js')
const { holdsDeclaredPermissionGlobally } = await import('../../middleware/platform-holder.js')
const { setActiveModel } = await import('../../authz-v2/model.js')

afterEach(() => { setActiveModel('v1'); clearAuthzCache(); queryOpa.mockClear() })

const orgRoute = { userContext: { email: 'desk@x.io' }, routeOptions: { config: { permission: 'org.members:write' } } }

describe('what follows the switch', () => {
  it('v1: super admin is asked of OPA; a platform holder passes an org route', async () => {
    expect(await isSuperAdmin('root@x.io')).toBe(true)
    expect(await holdsDeclaredPermissionGlobally({ ...orgRoute, routeOptions: { config: { permission: 'users:read' } } } as never)).toBe(true)
  })

  it('v2: nobody is a super admin by flag, and no platform permission counts inside an org', async () => {
    setActiveModel('v2')
    expect(await isSuperAdmin('root@x.io')).toBe(false)
    // support holds orgs.members:write on the platform — the org route still goes to the org clause.
    expect(await holdsDeclaredPermissionGlobally(orgRoute as never)).toBe(false)
    expect(queryOpa).not.toHaveBeenCalledWith('rbac/super_admin', expect.anything())
  })
})
