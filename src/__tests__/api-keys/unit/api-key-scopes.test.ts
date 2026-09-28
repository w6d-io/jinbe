import { describe, it, expect, beforeEach, vi } from 'vitest'

// The per-org scope catalog: permissions of routes on the org's sites, that the caller holds there
// (site grants ∪ org_grants of that org), under the env ceiling, never a wildcard.

const s = vi.hoisted(() => ({
  env: { API_KEY_ALLOWED_SCOPES: [] as string[] },
  orgServiceMap: {} as Record<string, string[]>,
  routeMaps: {} as Record<string, { rules: { method: string; path: string; permission?: string }[] }>,
  rights: {} as Record<string, string[]>, // `${email}|${site}` → permissions
  superAdmins: new Set<string>(),
  grants: {} as Record<string, string[]>, // `${org}|${email}` → groups
  groups: {} as Record<string, Record<string, string[]>>,
  roles: {} as Record<string, Record<string, string[]>>,
}))

vi.mock('../../../config/index.js', () => ({ env: s.env }))
vi.mock('../../../authz/opa.js', () => ({
  rights: vi.fn(async (email: string, app: string) => ({ groups: [], roles: [], permissions: s.rights[`${email}|${app}`] ?? [] })),
  isSuperAdmin: vi.fn(async (email: string) => s.superAdmins.has(email)),
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getOrgServiceMap: vi.fn(async () => s.orgServiceMap),
    getRouteMap: vi.fn(async (svc: string) => s.routeMaps[svc] ?? null),
    getGroups: vi.fn(async () => s.groups),
    getRoles: vi.fn(async (svc: string) => s.roles[svc] ?? null),
  },
}))
vi.mock('../../../services/org-grants.repository.js', () => ({
  orgGrantsRepository: { getForMember: vi.fn(async (org: string, email: string) => s.grants[`${org}|${email}`] ?? []) },
}))

import { scopeCatalog } from '../../../services/api-key-scopes.js'

const ACME = 'acme'

beforeEach(() => {
  s.env.API_KEY_ALLOWED_SCOPES = []
  s.orgServiceMap = { [ACME]: ['payroll', 'wiki'], globex: ['crm'] }
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
  s.superAdmins = new Set()
  s.grants = {}
  s.groups = {}
  s.roles = {}
})

describe('scopeCatalog', () => {
  it('offers only permissions the caller holds on this org\'s sites, grouped by site', async () => {
    // Matched exactly, as the gateway matches a site route: an ancestor held is not the permission.
    s.rights['ann@x.io|payroll'] = ['payroll:read', 'payroll.runs:read']
    s.rights['ann@x.io|wiki'] = ['wiki:read', 'payroll.runs:read']
    expect(await scopeCatalog(ACME, 'ann@x.io')).toEqual([
      { scope: 'payroll.runs:read', sites: ['payroll', 'wiki'] },
      { scope: 'wiki:read', sites: ['wiki'] },
    ])
  })

  it('counts org_grants of THIS org, in the site the group names only', async () => {
    s.grants[`${ACME}|bob@x.io`] = ['payroll-editors']
    s.groups['payroll-editors'] = { payroll: ['editor'], wiki: ['ghost-role'] }
    s.roles.payroll = { editor: ['payroll.runs:write'] }
    expect(await scopeCatalog(ACME, 'bob@x.io')).toEqual([{ scope: 'payroll.runs:write', sites: ['payroll'] }])
    // The same grant counts for nothing in another org.
    expect(await scopeCatalog('globex', 'bob@x.io')).toEqual([])
  })

  it('never offers a wildcard, even to a super admin, and nothing for an org with no sites', async () => {
    s.superAdmins.add('root@x.io')
    const all = (await scopeCatalog(ACME, 'root@x.io')).map((e) => e.scope)
    expect(all).toEqual(['payroll.runs:read', 'payroll.runs:write', 'wiki:read'])
    expect(all.some((p) => p.includes('*'))).toBe(false)
    expect(await scopeCatalog('nobody-org', 'root@x.io')).toEqual([])
  })

  it('a service "*" covers that site\'s routes only', async () => {
    s.rights['sam@x.io|payroll'] = ['*']
    expect((await scopeCatalog(ACME, 'sam@x.io')).map((e) => e.scope)).toEqual(['payroll.runs:read', 'payroll.runs:write'])
  })

  it('API_KEY_ALLOWED_SCOPES is a ceiling (dotted ancestors count), never a widening', async () => {
    s.superAdmins.add('root@x.io')
    s.env.API_KEY_ALLOWED_SCOPES = ['payroll:read', 'crm:read']
    expect(await scopeCatalog(ACME, 'root@x.io')).toEqual([{ scope: 'payroll.runs:read', sites: ['payroll', 'wiki'] }])
  })
})
