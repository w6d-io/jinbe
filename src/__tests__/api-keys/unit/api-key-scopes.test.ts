import { describe, it, expect, beforeEach, vi } from 'vitest'

// The per-org catalog of an org API key and its expansion: permissions asked by routes of the sites
// serving the org (never jinbe, kuma or global), their site roles, and groups binding only those
// sites' roles — under the env ceiling, matched exactly.

const s = vi.hoisted(() => ({
  env: { API_KEY_ALLOWED_SCOPES: [] as string[] },
  orgSites: {} as Record<string, string[]>,
  routeMaps: {} as Record<string, { rules: { method: string; path: string; permission?: string }[] }>,
  roles: {} as Record<string, Record<string, string[]>>,
  groups: {} as Record<string, Record<string, string[]>>,
}))

vi.mock('../../../config/index.js', () => ({ env: s.env }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getOrgSites: vi.fn(async () => s.orgSites),
    getGroups: vi.fn(async () => s.groups),
    getRoles: vi.fn(async (svc: string) => s.roles[svc] ?? null),
    getRouteMap: vi.fn(async (svc: string) => s.routeMaps[svc] ?? null),
  },
}))

import { expandScopes, loadKeyModel, scopeCatalog } from '../../../services/api-key-scopes.js'

const ACME = 'acme'

beforeEach(() => {
  s.env.API_KEY_ALLOWED_SCOPES = []
  s.orgSites = { [ACME]: ['jinbe', 'payroll', 'wiki'], globex: ['jinbe', 'crm'] }
  s.routeMaps = {
    jinbe: { rules: [{ method: 'GET', path: '/api/admin/users', permission: 'users:read' }] },
    payroll: { rules: [
      { method: 'GET', path: '/runs', permission: 'payroll.runs:read' },
      { method: 'POST', path: '/runs', permission: 'payroll.runs:write' },
      { method: 'GET', path: '/public' },
      { method: 'DELETE', path: '/all', permission: 'payroll:*' },
    ] },
    wiki: { rules: [{ method: 'GET', path: '/pages', permission: 'wiki:read' }, { method: 'GET', path: '/runs', permission: 'payroll.runs:read' }] },
    crm: { rules: [{ method: 'GET', path: '/deals', permission: 'crm:read' }] },
  }
  s.roles = {
    jinbe: { super_admin: ['users:read'] },
    payroll: { admin: ['payroll.runs:read', 'payroll.runs:write'], viewer: ['payroll.runs:read'], wild: ['*'] },
    wiki: { reader: ['wiki:read'] },
    crm: { sales: ['crm:read'] },
  }
  s.groups = {
    super_admins: { jinbe: ['super_admin'] },
    'payroll-ops': { payroll: ['admin'] },
    'acme-readers': { payroll: ['viewer'], wiki: ['reader'] },
    mixed: { payroll: ['viewer'], crm: ['sales'] },
  }
})

describe('scopeCatalog', () => {
  it("offers the permissions, roles and groups of the org's sites, each with what it stands for", async () => {
    expect(await scopeCatalog(ACME)).toEqual([
      { scope: 'group:acme-readers', kind: 'group', sites: ['payroll', 'wiki'], permissions: ['payroll.runs:read', 'wiki:read'] },
      { scope: 'group:payroll-ops', kind: 'group', sites: ['payroll'], permissions: ['payroll.runs:read', 'payroll.runs:write'] },
      { scope: 'payroll.runs:read', kind: 'permission', sites: ['payroll', 'wiki'], permissions: ['payroll.runs:read'] },
      { scope: 'payroll.runs:write', kind: 'permission', sites: ['payroll'], permissions: ['payroll.runs:write'] },
      { scope: 'role:payroll:admin', kind: 'role', sites: ['payroll'], permissions: ['payroll.runs:read', 'payroll.runs:write'] },
      { scope: 'role:payroll:viewer', kind: 'role', sites: ['payroll'], permissions: ['payroll.runs:read'] },
      { scope: 'role:wiki:reader', kind: 'role', sites: ['wiki'], permissions: ['wiki:read'] },
      { scope: 'wiki:read', kind: 'permission', sites: ['wiki'], permissions: ['wiki:read'] },
    ])
  })

  it("never the platform's own apps, a staff group, a group reaching another site, or a wildcard", async () => {
    const all = (await scopeCatalog(ACME)).map((e) => e.scope)
    for (const no of ['users:read', 'role:jinbe:super_admin', 'group:super_admins', 'group:mixed', 'payroll:*', 'role:payroll:wild', 'crm:read']) expect(all).not.toContain(no)
    expect(await scopeCatalog('nobody-org')).toEqual([])
  })

  it('API_KEY_ALLOWED_SCOPES is a ceiling of exact names, never a widening', async () => {
    s.env.API_KEY_ALLOWED_SCOPES = ['payroll.runs:read', 'crm:read']
    expect((await scopeCatalog(ACME)).map((e) => [e.scope, e.permissions])).toEqual([
      ['group:acme-readers', ['payroll.runs:read']],
      ['group:payroll-ops', ['payroll.runs:read']],
      ['payroll.runs:read', ['payroll.runs:read']],
      ['role:payroll:admin', ['payroll.runs:read']],
      ['role:payroll:viewer', ['payroll.runs:read']],
    ])
  })
})

describe('expandScopes: what the policy decides a key on (data.api_clients[…].scopes)', () => {
  it('permissions, roles and groups, as the sites define them now', async () => {
    const m = await loadKeyModel()
    expect(expandScopes(m, ACME, ['wiki:read', 'role:payroll:viewer', 'group:payroll-ops'])).toEqual(['payroll.runs:read', 'payroll.runs:write', 'wiki:read'])
    s.roles.payroll.viewer = ['payroll.runs:read', 'payroll.runs:write']
    expect(expandScopes(await loadKeyModel(), ACME, ['role:payroll:viewer'])).toEqual(['payroll.runs:read', 'payroll.runs:write'])
  })

  it('a site that stops serving the org takes its part of the key with it; unknown scopes stand for nothing', async () => {
    s.orgSites[ACME] = ['jinbe', 'wiki']
    expect(expandScopes(await loadKeyModel(), ACME, ['role:payroll:admin', 'payroll.runs:write', 'wiki:read', 'group:nope', 'role:x', 'users:read'])).toEqual(['wiki:read'])
  })

  it("another org's key expands over its own sites only", async () => {
    expect(expandScopes(await loadKeyModel(), 'globex', ['role:payroll:admin', 'crm:read', 'role:crm:sales'])).toEqual(['crm:read'])
  })
})
