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
  it('expands a super admin\'s `*` into the delegable catalogue permissions the routes declare', async () => {
    expect(declaredRoutes().length).toBeGreaterThan(150)
    expect(await platformScopes(ROOT)).toEqual([
      'access:check', 'access:read', 'audit:read', 'gateway:read',
      'groups:read', 'groups:write', 'org.keys:read', 'org.keys:revoke', 'org.members:read', 'org.members:write',
      // sessions:revoke is only asked by a DELETE, which no key may make (deletes are by hand)
      'org:read', 'org:write', 'recert:read', 'sessions:read',
      'settings:read', 'sites:apply', 'sites:read', 'sites:write',
      'stats:read', 'users.metadata:write', 'users:create', 'users:disable', 'users:read', 'users:recovery', 'users:send_login_link',
      'users:update', 'zones:read',
    ])
  })

  it('never offers `*`, a permission only refused routes ask for, or one no delegated caller may use', async () => {
    const all = await platformScopes(ROOT)
    // The catalogue's `never` (deletions, 2FA reset, key creation, approvals, the access model) and
    // every legacy name: a scope is a catalogue leaf.
    for (const p of ['*', 'org:manage_api_keys', 'org.keys:write', 'groups.members:revoke', 'users:delete', 'users:reset_second_factor',
      'sites:delete', 'sites.requests:approve', 'zones:delete', 'org.admins:write', 'policy.bundle:write',
      'recert:manage', 'settings.signin:write', 'settings.mcp:write', 'zones:write', 'gateway:apply', 'policy.bundle:read', 'audit:export',
      'admin:read', 'admin:write', 'admin:create']) {
      expect(all).not.toContain(p)
    }
  })

  it('offers a holder just what their groups give: users:read gives users:read, with no org at all', async () => {
    s.rights['sam@x.io'] = ['users:read']
    expect(await platformScopes('sam@x.io')).toEqual(['users:read'])
  })

  it('honours the legacy aliases the guards accept, for one release', async () => {
    s.rights['ada@x.io'] = ['admin:read']
    // admin:read stands for every catalogue read it used to open (and audit:export, through the audit scope).
    expect(await platformScopes('ada@x.io')).toEqual([
      'access:read', 'audit:read', 'gateway:read', 'groups:read', 'org.members:read', 'org:read',
      'recert:read', 'sessions:read', 'settings:read', 'sites:read', 'stats:read', 'users:read', 'zones:read',
    ])
  })

  it('gives an org\'s roster admin the org-management leaves (which org a call touches is decided per request)', async () => {
    s.members['olga@x.io'] = [ORG, 'globex']
    s.roster['olga@x.io'] = [ORG]
    // org:manage_users / org:manage_api_keys, as their catalogue leaves; key creation and revocation never.
    expect(await platformScopes('olga@x.io')).toEqual(['org.keys:read', 'org.keys:revoke', 'org.members:read', 'org.members:write'])
    s.roster['olga@x.io'] = []
    expect(await platformScopes('olga@x.io')).toEqual([])
  })

  it('counts org:manage_users granted in an org, only while a member of it', async () => {
    s.orgHeld[`${ORG}|gus@x.io`] = ['org:manage_users']
    expect(await platformScopes('gus@x.io')).toEqual([])
    s.members['gus@x.io'] = [ORG]
    expect(await platformScopes('gus@x.io')).toEqual(['org.members:read', 'org.members:write'])
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
    const catalog = await personalScopeCatalog('ada@x.io')
    expect(catalog.slice(0, 4)).toEqual([
      { scope: 'access:read', group: 'access' },
      { scope: 'audit:read', group: 'audit' },
      { scope: 'gateway:read', group: 'gateway' },
      { scope: 'groups:read', group: 'groups' },
    ])
    expect(catalog.filter((e) => e.group === 'org')).toEqual([
      { scope: 'org.members:read', group: 'org' },
      { scope: 'org:read', group: 'org' },
    ])
  })

  it('an org machine key keeps its site catalog: jinbe permissions are not offered there', async () => {
    await expect(apiKeyService.validateScopes(ORG, ROOT, ['admin:read'])).rejects.toMatchObject({ statusCode: 400, details: { invalid_scopes: ['admin:read'] } })
  })
})
