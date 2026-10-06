import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// Members join an organization by invitation, with consent: an org admin (org.members:write) invites
// an address — an account or not — and the person accepts, signed in with that address verified. The
// token is shown once; roles pass the holding rule when invited and again when accepted.

const ORG = '11111111-1111-4111-8111-111111111111'

const h = vi.hoisted(() => ({
  identities: {} as Record<string, { id: string; traits: { email: string }; verifiable_addresses: Array<{ via: string; value: string; verified: boolean }> }>,
  members: new Set<string>(), // `${id}|${org}`
  roles: {} as Record<string, string[]>,
  refusedFor: {} as Record<string, string[]>, // inviter → roles the holding rule refuses
  audits: [] as Array<{ type: string }>,
  guardRefuses: false,
}))

vi.mock('../../../services/redis-client.service.js', async () => {
  const { InlineRedisMock } = await import('../../sites/mocks.js')
  const redis = new InlineRedisMock()
  return { getRedisClient: () => redis, __redis: redis }
})
vi.mock('../../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => Promise<unknown>) => fn() }))
vi.mock('../../../middleware/require-org-permission.js', () => ({
  requireOrgPermission: () => async (_r: FastifyRequest, reply: FastifyReply) => {
    if (h.guardRefuses) return reply.status(403).send({ error: 'Forbidden', message: 'not in this org' })
  },
}))
vi.mock('../../../services/kratos.service.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  kratosService: {
    findByEmail: vi.fn(async (e: string) => Object.values(h.identities).find((i) => i.traits.email === e) ?? null),
    getIdentity: vi.fn(async (id: string) => h.identities[id]),
  },
}))
vi.mock('../../../services/organisation-store.js', () => ({
  organisationsById: vi.fn(async (ids: string[]) => ids.filter((id) => id === ORG).map((id) => ({ id, name: 'Acme', tenant: 'acme', attributes: {} }))),
}))
vi.mock('../../../services/org-membership.service.js', () => ({
  isMemberOf: vi.fn(async (i: { id: string }, org: string) => h.members.has(`${i.id}|${org}`)),
  joinOrganisation: vi.fn(async (i: { id: string }, org: string) => { h.members.add(`${i.id}|${org}`) }),
}))
vi.mock('../../../services/org-roles.repository.js', () => ({
  orgRolesRepository: {
    getForMember: vi.fn(async (_o: string, id: string) => h.roles[id] ?? []),
    setForMember: vi.fn(async (_o: string, id: string, roles: string[]) => { h.roles[id] = roles; return [] }),
  },
}))
vi.mock('../../../services/org-role-grants.js', () => ({
  orgRoleRefusals: vi.fn(async (actor: string, _org: string, roles: string[]) =>
    roles.filter((r) => (h.refusedFor[actor] ?? []).includes(r)).map((role) => ({ role, reason: 'grant_exceeds_own', reasons: ['missing_permissions'] }))),
}))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { notifyBindingsChanged: vi.fn(async () => {}) } }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async (e: { type: string }) => { h.audits.push(e) }) } }))

import { installRouteAccess } from '../../../policy/route-access.js'
import { declaredRoute } from '../../../policy/declared-routes.js'
import { orgInvitationRoutes, selfInvitationRoutes } from '../../../routes/org-invitations.routes.js'
import { orgInvitations } from '../../../services/org-invitations.js'

const person = (id: string, email: string, verified = true) => {
  h.identities[id] = { id, traits: { email }, verifiable_addresses: [{ via: 'email', value: email, verified }] }
}

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    const id = (request.headers['x-id'] as string) || 'admin'
    request.userContext = { id, email: h.identities[id]?.traits.email ?? 'admin@acme.io', name: 'X', aal: 'aal2' } as never
  })
  await app.register(orgInvitationRoutes, { prefix: '/api/organizations/:organizationId' })
  await app.register(selfInvitationRoutes, { prefix: '/api/me' })
  await app.ready()
})
afterAll(() => app.close())
beforeEach(async () => {
  ;((await import('../../../services/redis-client.service.js')) as unknown as { __redis: { clear: () => void } }).__redis.clear()
  h.identities = {}
  h.members = new Set()
  h.roles = {}
  h.refusedFor = {}
  h.audits = []
  h.guardRefuses = false
  person('admin', 'admin@acme.io')
})

const invite = (body: object, as = 'admin') => app.inject({ method: 'POST', url: `/api/organizations/${ORG}/invitations`, headers: { 'x-id': as }, payload: body })
const accept = (body: object, as: string) => app.inject({ method: 'POST', url: '/api/me/invitations/accept', headers: { 'x-id': as }, payload: body })

describe('inviting', () => {
  it('is org.members:write in that org; listing is org.members:read; accepting is the caller\'s own', () => {
    expect(declaredRoute('POST', '/api/organizations/:organizationId/invitations')).toMatchObject({ permission: 'org.members:write', org: 'organizationId' })
    expect(declaredRoute('GET', '/api/organizations/:organizationId/invitations')).toMatchObject({ permission: 'org.members:read' })
    expect(declaredRoute('DELETE', '/api/organizations/:organizationId/invitations/:invitationId')).toMatchObject({ permission: 'org.members:write' })
    expect(declaredRoute('POST', '/api/me/invitations/accept')).toMatchObject({ access: 'self' })
  })

  it('an address with no account: the token once, then listed without it; nobody joined yet', async () => {
    const res = await invite({ email: 'New@Example.com', roles: ['shop:member'] })
    expect(res.statusCode).toBe(201)
    const body = res.json()
    expect(body.token).toMatch(/^[A-Za-z0-9_-]{40,}$/)
    expect(body.invitation).toMatchObject({ org: ORG, email: 'new@example.com', roles: ['shop:member'], invitedBy: { email: 'admin@acme.io' } })
    expect(body.invitation).not.toHaveProperty('tokenHash')
    const list = (await app.inject({ url: `/api/organizations/${ORG}/invitations` })).json()
    expect(list.invitations).toHaveLength(1)
    expect(JSON.stringify(list)).not.toContain(body.token)
    expect(h.members.size).toBe(0)
    expect(h.audits.map((a) => a.type)).toContain('organization.invitation_created')
  })

  it('roles the inviter may not hand out are refused (holding rule); a member already in is a 409; another org is the guard\'s', async () => {
    h.refusedFor['admin@acme.io'] = ['shop:admin']
    expect((await invite({ email: 'x@y.io', roles: ['shop:admin'] })).statusCode).toBe(403)
    person('bob', 'bob@acme.io')
    h.members.add(`bob|${ORG}`)
    expect((await invite({ email: 'bob@acme.io' })).json()).toMatchObject({ code: 'already_member' })
    h.guardRefuses = true
    expect((await invite({ email: 'x@y.io' })).statusCode).toBe(403)
  })

  it('a new invitation of the same address replaces the pending one', async () => {
    const first = (await invite({ email: 'x@y.io' })).json()
    await invite({ email: 'x@y.io', roles: ['shop:member'] })
    expect(await orgInvitations.byToken(first.token)).toBeNull()
    expect(await orgInvitations.ofOrg(ORG)).toHaveLength(1)
  })
})

describe('accepting (consent)', () => {
  it('by token, signed in with that verified address: joins with the roles', async () => {
    const { token } = (await invite({ email: 'ann@x.io', roles: ['shop:member'] })).json()
    person('ann', 'ann@x.io')
    const res = await accept({ token }, 'ann')
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ organization: { id: ORG, name: 'Acme' }, roles: ['shop:member'], dropped: [] })
    expect(h.members.has(`ann|${ORG}`)).toBe(true)
    expect(h.roles.ann).toEqual(['shop:member'])
    // Single use.
    expect((await accept({ token }, 'ann')).statusCode).toBe(404)
  })

  it('a link forwarded to somebody else opens nothing; an unverified address waits', async () => {
    const { token } = (await invite({ email: 'ann@x.io' })).json()
    person('eve', 'eve@x.io')
    expect((await accept({ token }, 'eve')).json()).toMatchObject({ code: 'invitation_other_address' })
    person('ann', 'ann@x.io', false)
    expect((await accept({ token }, 'ann')).json()).toMatchObject({ code: 'email_not_verified' })
    expect(h.members.size).toBe(0)
  })

  it('by-token shows the invitation to its own address only, before accepting, verified or not', async () => {
    const { token } = (await invite({ email: 'ann@x.io', roles: ['shop:member'] })).json()
    const peek = (as: string, t = token) => app.inject({ url: `/api/me/invitations/by-token?token=${encodeURIComponent(t)}`, headers: { 'x-id': as } })
    person('ann', 'ann@x.io', false)
    const res = await peek('ann')
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ invitation: { org: ORG, organizationName: 'Acme', roles: ['shop:member'] }, verified: false })
    expect(res.json().invitation.tokenHash).toBeUndefined()
    person('eve', 'eve@x.io')
    const other = await peek('eve')
    expect(other.statusCode).toBe(403)
    expect(other.json()).toMatchObject({ code: 'invitation_other_address' })
    // A forwarded link never reveals who it was sent to.
    expect(JSON.stringify(other.json())).not.toContain('ann@x.io')
    expect((await peek('ann', 'x'.repeat(32))).statusCode).toBe(404)
    expect(h.members.size).toBe(0)
  })

  it('roles the inviter lost meanwhile are dropped, the membership stands', async () => {
    const { token } = (await invite({ email: 'ann@x.io', roles: ['shop:admin', 'shop:member'] })).json()
    h.refusedFor['admin@acme.io'] = ['shop:admin']
    person('ann', 'ann@x.io')
    expect((await accept({ token }, 'ann')).json()).toMatchObject({ roles: ['shop:member'], dropped: ['shop:admin'] })
  })

  it('an owner invited by the platform with a new organization keeps the owner role', async () => {
    const { token } = await orgInvitations.create({ org: ORG, email: 'boss@x.io', roles: ['jinbe:owner'], invitedBy: { id: 'dev', email: 'dev@staff.io' }, byPlatform: true })
    h.refusedFor['dev@staff.io'] = ['jinbe:owner']
    person('boss', 'boss@x.io')
    expect((await accept({ token }, 'boss')).json()).toMatchObject({ roles: ['jinbe:owner'], dropped: [] })
  })

  it('found by id from my own list; declined; an expired one is gone', async () => {
    await invite({ email: 'ann@x.io' })
    person('ann', 'ann@x.io')
    const mine = (await app.inject({ url: '/api/me/invitations', headers: { 'x-id': 'ann' } })).json().invitations
    expect(mine).toHaveLength(1)
    expect(mine[0]).toMatchObject({ organizationName: 'Acme' })
    expect((await app.inject({ method: 'POST', url: `/api/me/invitations/${mine[0].id}/decline`, headers: { 'x-id': 'ann' } })).statusCode).toBe(204)
    expect(await orgInvitations.forEmail('ann@x.io')).toEqual([])

    const old = await orgInvitations.create({ org: ORG, email: 'ann@x.io', roles: [], invitedBy: { id: null, email: 'admin@acme.io' } }, Date.now() - 8 * 86_400_000)
    expect(await orgInvitations.byToken(old.token)).toBeNull()
    expect(await orgInvitations.forEmail('ann@x.io')).toEqual([])
  })
})
