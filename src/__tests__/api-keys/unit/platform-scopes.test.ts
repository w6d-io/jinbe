import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest'
import type { FastifyInstance } from 'fastify'

// What a personal key may carry: the jinbe permissions its holder holds (groups; org layer in any org),
// read off the REAL route table (the server is built), never a wildcard, never one only a refused route asks for.

const s = vi.hoisted(() => ({
  superAdmins: new Set<string>(),
  rights: {} as Record<string, string[]>, // email → jinbe permissions
  members: {} as Record<string, string[]>, // email → orgs
  roster: {} as Record<string, string[]>, // email → administered orgs
  orgHeld: {} as Record<string, string[]>, // `${org}|${email}` → jinbe permissions via org grants
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
  scopeCatalog: vi.fn(async () => []),
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
  env.API_KEY_ALLOWED_SCOPES = []
  // The org-grant lookup keys heldIn's answer: the granted "group" is `${org}|${email}` here.
  vi.spyOn(orgGrantsRepository, 'getForMember').mockImplementation(async (org: string, email: string) => [`${org}|${email}`])
})

describe('platformScopes — what a personal key may carry', () => {
  it('expands a super admin\'s `*` into the concrete permissions the routes declare, minus refused-only ones', async () => {
    expect(declaredRoutes().length).toBeGreaterThan(150)
    expect(await platformScopes(ROOT)).toEqual([
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
    const all = await platformScopes(ROOT)
    // org:manage_api_keys only opens key routes; the users:* recovery set only account recovery;
    // sites:apply is ineligible outright; admin:create is a legacy rule beside org:manage_users.
    for (const p of ['*', 'org:manage_api_keys', 'users:recovery', 'users:send_login_link', 'users:reset_second_factor', 'sites:apply', 'admin:create']) {
      expect(all).not.toContain(p)
    }
  })

  it('offers a holder just what their groups give: users:read gives users:read, with no org at all', async () => {
    s.rights['sam@x.io'] = ['users:read']
    expect(await platformScopes('sam@x.io')).toEqual(['users:read'])
  })

  it('honours covers and the coarse permissions the guards accept', async () => {
    s.rights['ada@x.io'] = ['admin:read']
    // admin:read covers admin.organisation:read, refines to users:read / sessions:read, and reads the audit trail.
    expect(await platformScopes('ada@x.io')).toEqual(['admin.organisation:read', 'admin:read', 'audit:export', 'audit:read', 'sessions:read', 'users:read'])
  })

  it('gives an org\'s roster admin org:manage_users (which org a call touches is decided per request)', async () => {
    s.members['olga@x.io'] = [ORG, 'globex']
    s.roster['olga@x.io'] = [ORG]
    expect(await platformScopes('olga@x.io')).toEqual(['org:manage_users'])
    s.roster['olga@x.io'] = []
    expect(await platformScopes('olga@x.io')).toEqual([])
  })

  it('counts org:manage_users granted in an org, only while a member of it', async () => {
    s.orgHeld[`${ORG}|gus@x.io`] = ['org:manage_users']
    expect(await platformScopes('gus@x.io')).toEqual([])
    s.members['gus@x.io'] = [ORG]
    expect(await platformScopes('gus@x.io')).toEqual(['org:manage_users'])
  })

  it('ignores API_KEY_ALLOWED_SCOPES: that ceiling bounds org machine keys, not a holder\'s own key', async () => {
    const unbounded = await platformScopes(ROOT)
    env.API_KEY_ALLOWED_SCOPES = ['fleet:read']
    expect(await platformScopes(ROOT)).toEqual(unbounded)
    expect(await personalScopeCatalog(ROOT)).toContainEqual({ scope: 'users:read', group: 'users' })
  })
})

describe('personalScopeCatalog', () => {
  it('groups by resource root, then scope', async () => {
    s.rights['ada@x.io'] = ['admin:read']
    expect(await personalScopeCatalog('ada@x.io')).toEqual([
      { scope: 'admin.organisation:read', group: 'admin' },
      { scope: 'admin:read', group: 'admin' },
      { scope: 'audit:export', group: 'audit' },
      { scope: 'audit:read', group: 'audit' },
      { scope: 'sessions:read', group: 'sessions' },
      { scope: 'users:read', group: 'users' },
    ])
  })

  it('an org machine key keeps its site catalog: jinbe permissions are not offered there', async () => {
    await expect(apiKeyService.validateScopes(ORG, ROOT, ['admin:read'])).rejects.toMatchObject({ statusCode: 400, details: { invalid_scopes: ['admin:read'] } })
  })
})
