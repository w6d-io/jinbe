import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// J-3 / story 7: managing an org's API keys needs THAT org — its admin (roster / directory role),
// super_admin, or a member holding org:manage_api_keys there (site grants ∪ org_grants[that org]).
// J-1: the grant routes need that org's admin, or super_admin.

const ACME = '11111111-1111-1111-1111-111111111111'
const GLOBEX = '22222222-2222-2222-2222-222222222222'

const s = vi.hoisted(() => ({
  platform: [] as string[],
  platformFails: false,
  administers: {} as Record<string, boolean | null>,
  memberOf: [] as string[],
  memberFails: false,
  held: {} as Record<string, string[]>,
  orgGrantPerms: {} as Record<string, string[]>,
}))

vi.mock('../../../services/authorization-model.service.js', () => ({
  holdsPlatformPermission: vi.fn(async (_subject: string, required: string) => {
    if (s.platformFails) throw new Error('model unreadable')
    return s.platform.includes(required)
  }),
  rightsOf: vi.fn(async (_subject: string, org: string) => ({ groups: [], roles: [], permissions: s.held[org] ?? [] })),
}))
vi.mock('../../../services/org-admin.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../services/org-admin.js')>()
  return { ...real, administersOrganisation: vi.fn(async (_r: unknown, org: string) => (org in s.administers ? s.administers[org] : false)) }
})
vi.mock('../../../services/caller-organisations.js', () => ({
  callerOrganisations: vi.fn(async () => {
    if (s.memberFails) throw new Error('store down')
    return s.memberOf
  }),
}))
vi.mock('../../../services/org-grants.service.js', () => ({
  orgGrantPermissions: vi.fn(async (_email: string, org: string) => s.orgGrantPerms[org] ?? []),
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))

import { requireOrgAdmin, requireOrgPermission } from '../../../middleware/require-org-permission.js'
import { ORG_ADMIN_PERMISSIONS } from '../../../services/org-admin.js'
import { enforcedBy } from '../../../policy/declared-routes.js'

function run(guard: (req: FastifyRequest, rep: FastifyReply) => Promise<unknown>, org: string, user: { id?: string; email?: string } = { id: 'subject-x', email: 'x@acme.test' }) {
  const req = {
    userContext: user,
    method: 'GET',
    url: `/api/organizations/${org}/api-keys`,
    ip: '127.0.0.1',
    headers: {},
    params: { organizationId: org },
    log: { warn: vi.fn(), debug: vi.fn() },
  } as unknown as FastifyRequest
  const rep = {
    code: undefined as number | undefined,
    status(c: number) { this.code = c; return this },
    send() { return this },
  }
  return guard(req, rep as unknown as FastifyReply).then(() => rep.code)
}

const apiKeys = () => requireOrgPermission('org:manage_api_keys')

beforeEach(() => {
  s.platform = []
  s.platformFails = false
  s.administers = {}
  s.memberOf = []
  s.memberFails = false
  s.held = {}
  s.orgGrantPerms = {}
})

describe('requireOrgPermission("org:manage_api_keys") — API keys of THAT org', () => {
  it('org admins hold org:manage_api_keys', () => {
    expect(ORG_ADMIN_PERMISSIONS).toContain('org:manage_api_keys')
  })

  it('is marked with the permission it enforces (published route table)', () => {
    expect(enforcedBy(apiKeys())).toBe('org:manage_api_keys')
  })

  it('401 without an identity', async () => {
    expect(await run(apiKeys(), ACME, {})).toBe(401)
  })

  it('lets the org admin of that org in', async () => {
    s.administers = { [ACME]: true }
    s.memberOf = [ACME]
    expect(await run(apiKeys(), ACME)).toBeUndefined()
  })

  it('lets super_admin in (admin:write across the platform), member or not', async () => {
    s.platform = ['admin:write']
    expect(await run(apiKeys(), GLOBEX)).toBeUndefined()
  })

  it('lets a member holding org:manage_api_keys from a site grant in that org in', async () => {
    s.memberOf = [ACME]
    s.held = { [ACME]: ['org:manage_api_keys'] }
    expect(await run(apiKeys(), ACME)).toBeUndefined()
  })

  it('lets a member holding org:manage_api_keys from org_grants[that org] in', async () => {
    s.memberOf = [ACME]
    s.orgGrantPerms = { [ACME]: ['org:manage_api_keys'] }
    expect(await run(apiKeys(), ACME)).toBeUndefined()
  })

  it('refuses a service admin of ANOTHER org (403)', async () => {
    s.administers = { [GLOBEX]: true }
    s.memberOf = [GLOBEX]
    s.held = { [GLOBEX]: ['org:manage_api_keys', 'org:manage_users'] }
    s.orgGrantPerms = { [GLOBEX]: ['org:manage_api_keys'] }
    expect(await run(apiKeys(), ACME)).toBe(403)
  })

  it('refuses a non-member even if some grant names the permission there', async () => {
    s.held = { [ACME]: ['org:manage_api_keys'] }
    expect(await run(apiKeys(), ACME)).toBe(403)
  })

  it('refuses a member without the permission', async () => {
    s.memberOf = [ACME]
    s.held = { [ACME]: ['users:read'] }
    expect(await run(apiKeys(), ACME)).toBe(403)
  })

  it('503, not 403, when an authority could not be read and nothing admitted the caller', async () => {
    s.platformFails = true
    expect(await run(apiKeys(), ACME)).toBe(503)
    s.platformFails = false
    s.administers = { [ACME]: null }
    expect(await run(apiKeys(), ACME)).toBe(503)
    s.administers = {}
    s.memberFails = true
    expect(await run(apiKeys(), ACME)).toBe(503)
  })
})

describe('requireOrgAdmin — grant routes', () => {
  it('lets the org admin of that org and super_admin in', async () => {
    s.administers = { [ACME]: true }
    expect(await run(requireOrgAdmin(), ACME)).toBeUndefined()
    s.administers = {}
    s.platform = ['admin:write']
    expect(await run(requireOrgAdmin(), ACME)).toBeUndefined()
  })

  it('refuses a member holding permissions there but not administering it', async () => {
    s.memberOf = [ACME]
    s.held = { [ACME]: ['org:manage_users', 'users:assign_group'] }
    expect(await run(requireOrgAdmin(), ACME)).toBe(403)
  })

  it('refuses the admin of another org', async () => {
    s.administers = { [GLOBEX]: true }
    expect(await run(requireOrgAdmin(), ACME)).toBe(403)
  })

  it('503 when it cannot tell', async () => {
    s.administers = { [ACME]: null }
    expect(await run(requireOrgAdmin(), ACME)).toBe(503)
  })
})
