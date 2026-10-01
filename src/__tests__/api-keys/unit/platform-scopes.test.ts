import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest'
import type { FastifyInstance } from 'fastify'

// What a personal key may carry: the jinbe permissions its holder holds — platform ones (groups) and
// org ones held in at least one org — read off the REAL route table (the server is built), never one
// only a refused route asks for.

const s = vi.hoisted(() => ({
  rights: {} as Record<string, string[]>, // email → platform permissions in jinbe
  inOrg: {} as Record<string, Record<string, string[]>>, // email → org → org permissions
}))

vi.mock('../../../authz/opa.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../authz/opa.js')>()),
  rights: vi.fn(async (email: string) => ({ groups: [], roles: [], permissions: s.rights[email] ?? [] })),
  orgPermissionsByOrg: vi.fn(async (email: string) => s.inOrg[email] ?? {}),
}))
vi.mock('../../../services/api-key-scopes.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../services/api-key-scopes.js')>()),
  scopeCatalog: vi.fn(async () => []),
}))

import { declaredRoutes, resetDeclaredRoutes } from '../../../policy/declared-routes.js'
import { PLATFORM_PERMISSIONS } from '../../../policy/catalog.js'
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
  s.rights = { [ROOT]: [...PLATFORM_PERMISSIONS] }
  s.inOrg = { [ROOT]: { [ORG]: ['org.audit:read', 'org.keys:read', 'org.keys:revoke', 'org.keys:write', 'org.members:read', 'org.members:write'] } }
  env.API_KEY_ALLOWED_SCOPES = []
})

describe('platformScopes — what a personal key may carry', () => {
  it("a super admin's held permissions, kept to the delegable ones the routes declare", async () => {
    expect(declaredRoutes().length).toBeGreaterThan(150)
    expect(await platformScopes(ROOT)).toEqual([
      'access:check', 'access:read', 'audit:read', 'gateway:read',
      'groups.members:write', 'groups:read', 'groups:write', 'org.keys:read', 'org.keys:revoke', 'org.members:read', 'org.members:write',
      'orgs.members:write', 'orgs:read', 'orgs:write', 'recert:read', 'sessions:read',
      'settings:read', 'sites:apply', 'sites:read', 'sites:write',
      'stats:read', 'users.metadata:write', 'users:create', 'users:disable', 'users:read', 'users:recovery', 'users:send_login_link',
      'users:update', 'users:update_email', 'users:verify', 'zones:read',
    ])
  })

  it('never offers a permission no delegated caller may use, nor a retired name', async () => {
    const all = await platformScopes(ROOT)
    for (const p of ['*', 'org:manage_api_keys', 'org.keys:write', 'groups.members:revoke', 'users:delete', 'users:reset_second_factor',
      'sites:delete', 'sites.requests:approve', 'zones:delete', 'orgs.owners:write', 'policy.bundle:write',
      'recert:manage', 'settings.signin:write', 'settings.mcp:write', 'zones:write', 'gateway:apply', 'policy.bundle:read', 'audit:export',
      'admin:read', 'admin:write']) {
      expect(all).not.toContain(p)
    }
  })

  it('offers a holder just what their groups give: users:read gives users:read, with no org at all', async () => {
    s.rights['sam@x.io'] = ['users:read']
    expect(await platformScopes('sam@x.io')).toEqual(['users:read'])
  })

  it('a retired name grants nothing', async () => {
    s.rights['ada@x.io'] = ['admin:read', '*']
    expect(await platformScopes('ada@x.io')).toEqual([])
  })

  it("an org owner gets the org leaves they hold in some org (which org a call touches is decided per request)", async () => {
    s.inOrg['olga@x.io'] = { [ORG]: ['org.keys:read', 'org.keys:revoke', 'org.keys:write', 'org.members:read', 'org.members:write'], globex: [] }
    expect(await platformScopes('olga@x.io')).toEqual(['org.keys:read', 'org.keys:revoke', 'org.members:read', 'org.members:write'])
    s.inOrg['olga@x.io'] = {}
    expect(await platformScopes('olga@x.io')).toEqual([])
  })

  it('a platform permission never stands in for an org one', async () => {
    s.rights['pat@x.io'] = ['orgs.members:write']
    expect(await platformScopes('pat@x.io')).toEqual(['orgs.members:write'])
  })

  it("ignores API_KEY_ALLOWED_SCOPES: that ceiling bounds org machine keys, not a holder's own key", async () => {
    const unbounded = await platformScopes(ROOT)
    env.API_KEY_ALLOWED_SCOPES = ['fleet:read']
    expect(await platformScopes(ROOT)).toEqual(unbounded)
    expect(await personalScopeCatalog(ROOT)).toContainEqual({ scope: 'users:read', group: 'users' })
  })
})

describe('personalScopeCatalog', () => {
  it('groups by resource root, then scope', async () => {
    s.rights['ada@x.io'] = ['access:read', 'audit:read', 'gateway:read', 'groups:read', 'orgs:read']
    s.inOrg['ada@x.io'] = { [ORG]: ['org.members:read'] }
    const catalog = await personalScopeCatalog('ada@x.io')
    expect(catalog).toEqual([
      { scope: 'access:read', group: 'access' },
      { scope: 'audit:read', group: 'audit' },
      { scope: 'gateway:read', group: 'gateway' },
      { scope: 'groups:read', group: 'groups' },
      { scope: 'org.members:read', group: 'org' },
      { scope: 'orgs:read', group: 'orgs' },
    ])
  })

  it('an org machine key keeps its site catalog: jinbe permissions are not offered there', async () => {
    await expect(apiKeyService.validateScopes(ORG, ROOT, ['users:read'])).rejects.toMatchObject({ statusCode: 400, details: { invalid_scopes: ['users:read'] } })
  })
})
