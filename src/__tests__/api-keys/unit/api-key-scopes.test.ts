import { describe, it, expect, beforeEach, vi } from 'vitest'

// The per-org scope catalog: permissions of routes on the sites the org is entitled to, that the
// caller holds there (platform roles in that site ∪ org roles in that org for that site), under the
// env ceiling, matched exactly.

const s = vi.hoisted(() => ({
  env: { API_KEY_ALLOWED_SCOPES: [] as string[] },
  orgSites: {} as Record<string, string[]>,
  routeMaps: {} as Record<string, { rules: { method: string; path: string; permission?: string }[] }>,
  rights: {} as Record<string, string[]>, // `${email}|${site}` → platform permissions
  inOrg: {} as Record<string, Record<string, string[]>>, // `${email}|${site}` → org → org permissions
}))

vi.mock('../../../config/index.js', () => ({ env: s.env }))
vi.mock('../../../authz/opa.js', () => ({
  rights: vi.fn(async (email: string, app: string) => ({ groups: [], roles: [], permissions: s.rights[`${email}|${app}`] ?? [] })),
  orgPermissionsByOrg: vi.fn(async (email: string, app: string) => s.inOrg[`${email}|${app}`] ?? {}),
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getOrgSites: vi.fn(async () => s.orgSites),
    getRouteMap: vi.fn(async (svc: string) => s.routeMaps[svc] ?? null),
  },
}))

import { scopeCatalog } from '../../../services/api-key-scopes.js'

const ACME = 'acme'

beforeEach(() => {
  s.env.API_KEY_ALLOWED_SCOPES = []
  s.orgSites = { [ACME]: ['payroll', 'wiki'], globex: ['crm'] }
  s.routeMaps = {
    payroll: { rules: [
      { method: 'GET', path: '/runs', permission: 'payroll.runs:read' },
      { method: 'POST', path: '/runs', permission: 'payroll.runs:write' },
      { method: 'GET', path: '/public' },
      { method: 'DELETE', path: '/all', permission: 'payroll:*' },
    ] },
    wiki: { rules: [{ method: 'GET', path: '/pages', permission: 'wiki:read' }, { method: 'GET', path: '/runs', permission: 'payroll.runs:read' }] },
    crm: { rules: [{ method: 'GET', path: '/deals', permission: 'crm:read' }] },
  }
  s.rights = {}
  s.inOrg = {}
})

describe('scopeCatalog', () => {
  it("offers only permissions the caller holds on this org's sites, grouped by site", async () => {
    // Matched exactly, as the gateway matches a site route: an ancestor held is not the permission.
    s.rights['ann@x.io|payroll'] = ['payroll:read', 'payroll.runs:read']
    s.rights['ann@x.io|wiki'] = ['wiki:read', 'payroll.runs:read']
    expect(await scopeCatalog(ACME, 'ann@x.io')).toEqual([
      { scope: 'payroll.runs:read', sites: ['payroll', 'wiki'] },
      { scope: 'wiki:read', sites: ['wiki'] },
    ])
  })

  it('counts org roles held in THIS org, for that site only', async () => {
    s.inOrg['bob@x.io|payroll'] = { [ACME]: ['payroll.runs:write'] }
    expect(await scopeCatalog(ACME, 'bob@x.io')).toEqual([{ scope: 'payroll.runs:write', sites: ['payroll'] }])
    // The same org role counts for nothing in another org.
    expect(await scopeCatalog('globex', 'bob@x.io')).toEqual([])
  })

  it('never offers a wildcard; a held `*` grants nothing; nothing for an org with no sites', async () => {
    s.rights['sam@x.io|payroll'] = ['*', 'payroll.runs:read', 'payroll.runs:write', 'payroll:*']
    const all = (await scopeCatalog(ACME, 'sam@x.io')).map((e) => e.scope)
    expect(all).toEqual(['payroll.runs:read', 'payroll.runs:write'])
    expect(await scopeCatalog('nobody-org', 'sam@x.io')).toEqual([])
  })

  it('API_KEY_ALLOWED_SCOPES is a ceiling of exact names, never a widening', async () => {
    s.rights['root@x.io|payroll'] = ['payroll.runs:read', 'payroll.runs:write']
    s.rights['root@x.io|wiki'] = ['payroll.runs:read', 'wiki:read']
    s.env.API_KEY_ALLOWED_SCOPES = ['payroll.runs:read', 'crm:read']
    expect(await scopeCatalog(ACME, 'root@x.io')).toEqual([{ scope: 'payroll.runs:read', sites: ['payroll', 'wiki'] }])
  })
})
