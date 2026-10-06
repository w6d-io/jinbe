import { beforeEach, describe, expect, it, vi } from 'vitest'
import { InlineRedisMock } from './mocks.js'
import { payrollSite, platform } from './fixtures.js'
import type { Site } from '../../sites/schemas.js'

const redis = new InlineRedisMock()
const state = vi.hoisted(() => ({
  live: null as Site | null,
  identity: null as Record<string, unknown> | null,
  groups: new Map<string, string[]>(),
  orgSites: {} as Record<string, string[]>,
  orgsOf: [] as string[],
  created: [] as Array<{ name: string; tenant: string }>,
  owners: [] as Array<[string, string, string[]]>,
  joined: [] as Array<[string, string]>,
  registration: { mode: 'closed', allowEmails: [] as string[], allowDomains: [] as string[], denyDomains: [] as string[], blockDisposable: false },
}))

vi.mock('../../services/redis-client.service.js', () => ({ getRedisClient: () => redis }))
vi.mock('../../services/redis-lock.js', () => ({ withRedisLock: async (_n: string, fn: () => Promise<unknown>) => fn() }))
vi.mock('../../sites/login.js', () => ({
  liveSite: async (name: string) => (state.live?.name === name ? state.live : null),
  liveSiteByHost: async (host: string) => (state.live?.address.host === host ? state.live : null),
}))
vi.mock('../../services/kratos.service.js', () => ({ kratosService: { getIdentity: async () => state.identity } }))
vi.mock('../../services/organisation-store.js', () => ({
  groupsForSubjects: async (ids: string[]) => new Map(ids.map((id) => [id, state.groups.get(id) ?? []])),
  addToGroup: async (id: string, g: string) => { state.groups.set(id, [...(state.groups.get(id) ?? []), g]) },
  removeFromGroup: async (id: string, g: string) => { state.groups.set(id, (state.groups.get(id) ?? []).filter((x) => x !== g)) },
  createOrganisation: async (input: { name: string; tenant: string }) => { state.created.push(input); return { id: `org-${state.created.length}`, ...input } },
}))
vi.mock('../../services/org-membership.service.js', () => ({
  organisationsOf: async () => state.orgsOf,
  joinOrganisation: async (identity: { id: string }, org: string) => { state.joined.push([identity.id, org]) },
}))
vi.mock('../../services/org-roles.repository.js', () => ({
  orgRolesRepository: { setForMember: async (org: string, id: string, roles: string[]) => { state.owners.push([org, id, roles]); return roles } },
}))
vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getOrgSites: async () => state.orgSites,
    setOrgSites: async (org: string, sites: string[]) => { state.orgSites[org] = sites },
  },
}))
vi.mock('../../services/rbac.service.js', () => ({ rbacService: { notifyBindingsChanged: async () => {} } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: async () => {} } }))
vi.mock('../../sign-in-protection/settings.js', async (orig) => ({
  ...(await orig<typeof import('../../sign-in-protection/settings.js')>()),
  getSignInProtection: async () => ({ captcha: { flows: { registration: false, login: false, recovery: false, verification: false }, failMode: 'closed' }, registration: state.registration }),
}))

const { render } = await import('../../sites/render.js')
const { siteSchema } = await import('../../sites/schemas.js')
const { signUpWidens } = await import('../../sites/apply.service.js')
const svc = await import('../../sites/signup/service.js')
const { signUpStore } = await import('../../sites/signup/store.js')
const { guardFlow } = await import('../../sign-in-protection/guard.js')

const ID = '22222222-2222-2222-2222-222222222222'
const open = (over: Partial<NonNullable<Site['signUp']>> = {}): Site =>
  payrollSite({ roles: 'standard', signUp: { mode: 'open', domains: [], roles: ['user'], orgs: 'personal', ...over } })
const person = (email: string, verified: boolean, traits: Record<string, unknown> = {}) => ({
  id: ID,
  traits: { email, ...traits },
  verifiable_addresses: [{ value: email, via: 'email', verified }],
})

beforeEach(() => {
  redis.clear()
  state.live = open()
  state.identity = person('jane@client.com', true, { name: 'Jane Doe' })
  state.groups = new Map()
  state.orgSites = {}
  state.orgsOf = []
  state.created = []
  state.owners = []
  state.joined = []
  state.registration = { mode: 'closed', allowEmails: [], allowDomains: [], denyDomains: [], blockDisposable: false }
})

describe('the signUp intent', () => {
  it('renders the <site>-users group bound to the sign-up roles, and `user` in the standard set', () => {
    const out = render(open(), platform)
    expect(out.roles.user).toEqual(['payroll:list', 'payroll:read', 'payroll:use'])
    expect(out.groups.platform['payroll-users']).toEqual({ payroll: ['user'] })
  })

  it('keeps the group when sign-up is closed (who joined keeps access)', () => {
    expect(render(open({ mode: 'closed' }), platform).groups.platform['payroll-users']).toEqual({ payroll: ['user'] })
  })

  it('refuses a sign-up role the site does not define', () => {
    expect(render(open({ roles: ['ghost'] }), platform).checks).toContainEqual(expect.objectContaining({ level: 'error', code: 'unknown_role', path: 'signUp.roles' }))
  })

  it('needs domains in domains mode, and keeps the sign-up group name out of groups', () => {
    expect(siteSchema.safeParse(open({ mode: 'domains', domains: [] })).success).toBe(false)
    const taken = { ...open(), groups: { platform: { 'payroll-users': ['admin'] }, orgGrantable: {} } }
    expect(siteSchema.safeParse(taken).success).toBe(false)
  })
})

describe('widening sign-up needs sites.signup:write', () => {
  const s = (mode: 'closed' | 'open' | 'domains', domains: string[] = [], roles = ['user']) => ({ mode, domains, roles, orgs: 'personal' as const })
  it.each([
    ['closed → open', undefined, s('open'), true],
    ['closed → closed', s('closed'), s('closed'), false],
    ['domains → open', s('domains', ['a.com']), s('open'), true],
    ['one more domain', s('domains', ['a.com']), s('domains', ['a.com', 'b.com']), true],
    ['one domain fewer', s('domains', ['a.com', 'b.com']), s('domains', ['a.com']), false],
    ['one more role', s('open'), s('open', [], ['user', 'editor']), true],
    ['open → closed', s('open'), s('closed'), false],
  ])('%s', (_label, before, after, widens) => {
    expect(signUpWidens(before, after)).toBe(widens)
  })
})

describe('naming the organisation', () => {
  it('uses the company, else the first name, else the address', () => {
    expect(svc.organisationNameFor(person('a@b.com', true, { company: ' Acme ' }) as never)).toBe('Acme')
    expect(svc.organisationNameFor(person('a@b.com', true, { name: 'Jane Doe' }) as never)).toBe("Jane's organization")
    expect(svc.organisationNameFor(person('bob@b.com', true) as never)).toBe("bob's organization")
  })
  it('gives every org its own tenant', () => {
    expect(svc.tenantFor("Jane's organization")).toMatch(/^jane-s-organization-[0-9a-f]{6}$/)
    expect(svc.tenantFor("Jane's organization")).not.toBe(svc.tenantFor("Jane's organization"))
  })
})

describe('joining', () => {
  it('a verified sign-up joins the group, gets an org it owns, entitled to the site', async () => {
    const out = await svc.joinSite(ID, 'payroll', 'sign-up')
    expect(out).toMatchObject({ joined: true, group: 'payroll-users', organization: { id: 'org-1', name: "Jane's organization", created: true } })
    expect(state.groups.get(ID)).toEqual(['payroll-users'])
    expect(state.orgSites['org-1']).toEqual(['jinbe', 'payroll'])
    expect(state.owners).toEqual([['org-1', ID, ['jinbe:owner']]])
    expect(await signUpStore.orgsOf('payroll')).toEqual(['org-1'])
  })

  it('is idempotent and makes no second org for somebody already in one the site serves', async () => {
    state.orgsOf = ['org-x']
    state.orgSites = { 'org-x': ['jinbe', 'payroll'] }
    await svc.joinSite(ID, 'payroll', 'sign-up')
    await svc.joinSite(ID, 'payroll', 'continue')
    expect(state.created).toEqual([])
    expect(state.groups.get(ID)).toEqual(['payroll-users'])
  })

  it('waits for a verified address', async () => {
    state.identity = person('jane@client.com', false)
    expect(await svc.joinSite(ID, 'payroll', 'sign-up')).toEqual({ joined: false, site: 'payroll', reason: 'email_not_verified' })
    expect(state.groups.get(ID)).toBeUndefined()
  })

  it('refuses when sign-up is closed, and a domain the site does not list', async () => {
    state.live = open({ mode: 'closed' })
    expect(await svc.joinSite(ID, 'payroll', 'continue')).toMatchObject({ joined: false, reason: 'sign_up_closed' })
    state.live = open({ mode: 'domains', domains: ['other.com'] })
    expect(await svc.joinSite(ID, 'payroll', 'continue')).toMatchObject({ joined: false, reason: 'domain_not_allowed' })
  })

  it('an invited colleague joins the group without an org of their own, even after sign-up closed', async () => {
    state.live = open({ mode: 'closed' })
    expect(await svc.joinSite(ID, 'payroll', 'invite')).toMatchObject({ joined: true, organization: null })
    expect(state.created).toEqual([])
  })

  it('orgs: domain joins the org that proved the domain, else a personal one', async () => {
    state.live = open({ orgs: 'domain' })
    await signUpStore.putDomain({ domain: 'client.com', org: 'org-acme', token: 't', verified: true, claimedAt: 'x' })
    expect(await svc.joinSite(ID, 'payroll', 'sign-up')).toMatchObject({ joined: true, organization: { id: 'org-acme', created: false } })
    expect(state.joined).toContainEqual([ID, 'org-acme'])
    expect(state.created).toEqual([])
  })

  it('an unverified domain claim brings nobody in', async () => {
    state.live = open({ orgs: 'domain' })
    await signUpStore.putDomain({ domain: 'client.com', org: 'org-acme', token: 't', verified: false, claimedAt: 'x' })
    expect(await svc.joinSite(ID, 'payroll', 'sign-up')).toMatchObject({ organization: { id: 'org-1', created: true } })
  })

  it('the verification hook joins the sites the address signed up through', async () => {
    await signUpStore.addPending('Jane@Client.com', 'payroll')
    await svc.onIdentityEvent(ID)
    expect(state.groups.get(ID)).toEqual(['payroll-users'])
    expect(await signUpStore.pending('jane@client.com')).toEqual([])
  })
})

describe('the default organization (organizations on)', () => {
  const host = 'payroll.dev.example.com'

  it('entering a site with organizations on gives an account an org it owns, sign-up open or not', async () => {
    state.live = payrollSite()
    const out = await svc.continueTo(ID, host)
    expect(out).toMatchObject({ joined: false, reason: 'sign_up_closed', organization: { id: 'org-1', created: true } })
    expect(state.owners).toEqual([['org-1', ID, ['jinbe:owner']]])
    expect(state.orgSites['org-1']).toEqual(['jinbe', 'payroll'])
    // Once: the org it owns is served by the site now.
    state.orgsOf = ['org-1']
    expect(await svc.continueTo(ID, host)).toMatchObject({ organization: { id: 'org-1', created: false } })
    expect(state.created).toHaveLength(1)
  })

  it('through an open sign-up, the same org (no second one)', async () => {
    expect(await svc.continueTo(ID, host)).toMatchObject({ joined: true, organization: { id: 'org-1', created: true } })
    expect(state.created).toHaveLength(1)
  })

  it('never on a site with organizations off; never for an unverified address; not when sign-up says invite or none', async () => {
    state.live = { ...payrollSite({ organizations: { enabled: false }, orgs: [] }) }
    expect(await svc.continueTo(ID, host)).not.toHaveProperty('organization')
    state.live = payrollSite()
    state.identity = person('jane@client.com', false)
    expect(await svc.continueTo(ID, host)).not.toHaveProperty('organization')
    state.identity = person('jane@client.com', true)
    for (const orgs of ['invite', 'none'] as const) {
      state.live = payrollSite({ signUp: { mode: 'closed', domains: [], roles: ['viewer'], orgs } })
      expect(await svc.continueTo(ID, host)).not.toHaveProperty('organization')
    }
    expect(state.created).toEqual([])
  })
})

describe('the registration guard', () => {
  const reg = (returnTo?: string) => guardFlow({ flow: 'registration', method: 'password', email: 'jane@client.com', traits: { email: 'jane@client.com' }, returnTo })

  it('lets a sign-up through an open site in while the platform sign-up is closed, and remembers it', async () => {
    expect(await reg('https://payroll.dev.example.com/home')).toMatchObject({ allow: true })
    expect(await signUpStore.pending('jane@client.com')).toEqual([expect.objectContaining({ site: 'payroll' })])
  })

  it('refuses without a site, or through a closed one', async () => {
    expect(await reg()).toMatchObject({ allow: false, result: 'registration_closed' })
    state.live = open({ mode: 'closed' })
    expect(await reg('https://payroll.dev.example.com/')).toMatchObject({ allow: false, result: 'registration_closed' })
  })

  it('lets an invited address register whatever the sign-up policy says — only through its invitation link', async () => {
    const { orgInvitations } = await import('../../services/org-invitations.js')
    const { token } = await orgInvitations.create({ org: 'org-acme', email: 'jane@client.com', roles: [], invitedBy: { id: null, email: 'admin@acme.io' } })
    expect(await reg(`https://auth.example.com/invitation?token=${token}`)).toMatchObject({ allow: true })
    // Holding an invitation opens nothing else: no token, a wrong one, or another address's.
    expect(await reg()).toMatchObject({ allow: false, result: 'registration_closed' })
    expect(await reg('https://auth.example.com/invitation?token=nope')).toMatchObject({ allow: false })
    const other = await orgInvitations.create({ org: 'org-acme', email: 'someone@else.com', roles: [], invitedBy: { id: null, email: 'admin@acme.io' } })
    expect(await reg(`https://auth.example.com/invitation?token=${other.token}`)).toMatchObject({ allow: false })
  })

  it("applies the site's domains", async () => {
    state.live = open({ mode: 'domains', domains: ['other.com'] })
    expect(await reg('https://payroll.dev.example.com/')).toMatchObject({ allow: false, result: 'registration_not_allowed' })
  })
})
