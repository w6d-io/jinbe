import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest'
import type { FastifyInstance } from 'fastify'

// The personal-key catalog: the org's site scopes ∪ jinbe's own permissions the caller holds, read off
// the REAL route table (the server is built), never a wildcard, never one only a refused route asks for.

const s = vi.hoisted(() => ({
  superAdmins: new Set<string>(),
  rights: {} as Record<string, string[]>, // email → jinbe permissions
  members: {} as Record<string, string[]>, // email → orgs
  roster: {} as Record<string, string[]>, // email → administered orgs
  orgHeld: {} as Record<string, string[]>, // `${org}|${email}` → jinbe permissions via org grants
  sites: {} as Record<string, { scope: string; sites: string[] }[]>, // org → site catalog
}))

vi.mock('../../../authz/opa.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../authz/opa.js')>()),
  isSuperAdmin: vi.fn(async (email: string) => s.superAdmins.has(email)),
  rights: vi.fn(async (email: string) => ({ groups: [], roles: [], permissions: s.rights[email] ?? [] })),
  memberOrgs: vi.fn(async (email: string) => s.members[email] ?? []),
  manageableOrgs: vi.fn(async (email: string) => s.roster[email] ?? []),
}))
vi.mock('../../../services/api-key-scopes.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../services/api-key-scopes.js')>()),
  scopeCatalog: vi.fn(async (org: string) => s.sites[org] ?? []),
  heldIn: vi.fn(async (email: string, _app: string, granted: readonly string[]) => (granted.length ? s.orgHeld[granted[0]] ?? [] : [])),
}))

import { declaredRoutes, resetDeclaredRoutes } from '../../../policy/declared-routes.js'
import { orgGrantsRepository } from '../../../services/org-grants.repository.js'
import { personalScopeCatalog, platformScopes } from '../../../services/platform-scopes.js'
import { apiKeyService } from '../../../services/api-key.service.js'
import { env } from '../../../config/index.js'

const ORG = 'acme'
const ROOT = 'root@x.io'

let app: FastifyInstance
beforeAll(async () => {
  process.env.NODE_ENV = 'development'
  process.env.DEV_BYPASS_AUTH = 'true'
  process.env.ENCRYPTION_KEY = 'x'.repeat(32)
  process.env.DEV_USER_EMAIL = 'dev@localhost.io'
  resetDeclaredRoutes()
  const { buildServer } = await import('../../../server.js')
  app = await buildServer()
}, 30_000)
afterAll(async () => { await app?.close() })

beforeEach(() => {
  s.superAdmins = new Set([ROOT])
  s.rights = { [ROOT]: ['*'] }
  s.members = {}
  s.roster = {}
  s.orgHeld = {}
  s.sites = {}
  env.API_KEY_ALLOWED_SCOPES = []
  // The org-grant lookup keys heldIn's answer: the granted "group" is `${org}|${email}` here.
  vi.spyOn(orgGrantsRepository, 'getForMember').mockImplementation(async (org: string, email: string) => [`${org}|${email}`])
})

describe('platformScopes — jinbe permissions on a personal key', () => {
  it('expands a super admin\'s `*` into the concrete permissions the routes declare, minus refused-only ones', async () => {
    expect(declaredRoutes().length).toBeGreaterThan(150)
    expect(await platformScopes(ORG, ROOT)).toEqual([
      'admin.organisation:read',
      'admin.organisation:write',
      'admin:read',
      'admin:write',
      'audit:export',
      'audit:read',
      'org:manage_users',
      'sessions:read',
      'sessions:revoke',
      'users:create',
      'users:delete',
      'users:read',
      'users:update',
    ])
  })

  it('never offers `*`, a permission only refused routes ask for, or one no delegated caller may use', async () => {
    const all = await platformScopes(ORG, ROOT)
    // org:manage_api_keys only opens key routes; the users:* recovery set only account recovery;
    // sites:apply is ineligible outright; admin:create is a legacy rule beside org:manage_users.
    for (const p of ['*', 'org:manage_api_keys', 'users:recovery', 'users:send_login_link', 'users:reset_second_factor', 'sites:apply', 'admin:create']) {
      expect(all).not.toContain(p)
    }
  })

  it('offers a member just what they hold: users:read gives users:read', async () => {
    s.rights['sam@x.io'] = ['users:read']
    s.members['sam@x.io'] = [ORG]
    expect(await platformScopes(ORG, 'sam@x.io')).toEqual(['users:read'])
  })

  it('honours covers and the coarse permissions the guards accept', async () => {
    s.rights['ada@x.io'] = ['admin:read']
    s.members['ada@x.io'] = [ORG]
    // admin:read covers admin.organisation:read, refines to users:read / sessions:read, and reads the audit trail.
    expect(await platformScopes(ORG, 'ada@x.io')).toEqual(['admin.organisation:read', 'admin:read', 'audit:export', 'audit:read', 'sessions:read', 'users:read'])
  })

  it('gives THIS org\'s roster admin org:manage_users, and nothing in another org', async () => {
    s.members['olga@x.io'] = [ORG, 'globex']
    s.roster['olga@x.io'] = [ORG]
    expect(await platformScopes(ORG, 'olga@x.io')).toEqual(['org:manage_users'])
    expect(await platformScopes('globex', 'olga@x.io')).toEqual([])
  })

  it('counts org:manage_users granted in this org, only while a member', async () => {
    s.orgHeld[`${ORG}|gus@x.io`] = ['org:manage_users']
    expect(await platformScopes(ORG, 'gus@x.io')).toEqual([])
    s.members['gus@x.io'] = [ORG]
    expect(await platformScopes(ORG, 'gus@x.io')).toEqual(['org:manage_users'])
  })

  it('stays under API_KEY_ALLOWED_SCOPES', async () => {
    env.API_KEY_ALLOWED_SCOPES = ['admin:read']
    expect(await platformScopes(ORG, ROOT)).toEqual(['admin:read', 'admin.organisation:read'].sort())
  })
})

describe('personalScopeCatalog', () => {
  it('yields platform scopes for an org with no sites, grouped under `platform`', async () => {
    s.rights['sam@x.io'] = ['users:read']
    expect(await personalScopeCatalog(ORG, 'sam@x.io')).toEqual([{ scope: 'users:read', sites: ['platform'], kind: 'platform' }])
  })

  it('merges a scope both a site and jinbe ask for into one entry', async () => {
    s.rights['sam@x.io'] = ['users:read']
    s.sites[ORG] = [{ scope: 'payroll:read', sites: ['payroll'] }, { scope: 'users:read', sites: ['hr'] }]
    expect(await personalScopeCatalog(ORG, 'sam@x.io')).toEqual([
      { scope: 'payroll:read', sites: ['payroll'], kind: 'site' },
      { scope: 'users:read', sites: ['hr', 'platform'], kind: 'site' },
    ])
  })

  it('personal keys validate against the union; org machine keys keep the site catalog', async () => {
    s.sites[ORG] = [{ scope: 'payroll:read', sites: ['payroll'] }]
    await expect(apiKeyService.validateScopes(ORG, ROOT, ['payroll:read', 'admin:read'], personalScopeCatalog)).resolves.toBeUndefined()
    await expect(apiKeyService.validateScopes(ORG, ROOT, ['admin:read'])).rejects.toMatchObject({ statusCode: 400, details: { invalid_scopes: ['admin:read'] } })
    await expect(apiKeyService.validateScopes(ORG, ROOT, ['*'], personalScopeCatalog)).rejects.toMatchObject({ statusCode: 400 })
  })
})
