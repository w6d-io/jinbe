import { describe, it, expect, beforeEach, vi } from 'vitest'

// The kratos organisation store, end to end over a fake Kratos admin API and an in-memory Redis:
// the registry (CRUD, entitlements), membership on the identity (primary + list + roles), isolation
// between organisations, no lost update under concurrent writers, the fan-out after every write, and
// the OPAL bindings shape — which must not change because the store did.

const ACME = '11111111-1111-4111-8111-111111111111'
const GLOBEX = '22222222-2222-4222-8222-222222222222'
const INITECH = '33333333-3333-4333-8333-333333333333'
const BOB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const ALICE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

const h = vi.hoisted(() => {
  // ─── In-memory Redis: the commands the registry, the lock and the home cache use ───
  const kv = new Map<string, string>()
  const hashes = new Map<string, Map<string, string>>()
  const hash = (k: string) => hashes.get(k) ?? hashes.set(k, new Map()).get(k)!
  const redis = {
    set: async (k: string, v: string, _px: string, _ttl: number, nx: string) => {
      if (nx === 'NX' && kv.has(k)) return null
      kv.set(k, v)
      return 'OK'
    },
    eval: async (_lua: string, _n: number, k: string, token: string) => (kv.get(k) === token ? (kv.delete(k), 1) : 0),
    incr: async () => 1,
    hget: async (k: string, f: string) => hash(k).get(f) ?? null,
    hset: async (k: string, f: string, v: string) => (hash(k).set(f, v), 1),
    hdel: async (k: string, f: string) => (hash(k).delete(f) ? 1 : 0),
    hexists: async (k: string, f: string) => (hash(k).has(f) ? 1 : 0),
    hgetall: async (k: string) => Object.fromEntries(hash(k)),
    hmget: async (k: string, ...fs: string[]) => fs.map((f) => hash(k).get(f) ?? null),
  }
  return {
    kv,
    hashes,
    redis,
    identities: new Map<string, Record<string, unknown>>(),
    patches: [] as Array<{ id: string; body: Array<{ op: string; path: string; value?: unknown }> }>,
    delayMs: 0,
    invalidateBundle: vi.fn(async () => {}),
  }
})

vi.mock('../../../config/index.js', () => ({
  env: { KRATOS_ADMIN_URL: 'http://kratos-admin', KRATOS_REQUEST_TIMEOUT_MS: 5000, ORGANISATION_SOURCE: 'directory' },
}))
vi.mock('../../../services/redis-client.service.js', () => ({ getRedisClient: () => h.redis }))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { invalidateBundle: h.invalidateBundle } }))

// ─── A fake Kratos admin API: list, get, and JSON Patch with add/replace/remove, like v26.2 ───
const pause = () => new Promise((r) => setTimeout(r, h.delayMs))
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
function applyPatch(identity: Record<string, unknown>, ops: Array<{ op: string; path: string; value?: unknown }>) {
  const next = structuredClone(identity)
  for (const { op, path, value } of ops) {
    if (!['add', 'replace', 'remove'].includes(op)) throw new Error(`unsupported operation: ${op}`)
    const [, top, key] = path.split('/')
    if (!key) {
      if (op === 'remove') delete next[top]
      else next[top] = value
      continue
    }
    const parent = ((next[top] as Record<string, unknown> | null) ?? {}) as Record<string, unknown>
    const k = key.replace(/~1/g, '/').replace(/~0/g, '~')
    if (op === 'remove') delete parent[k]
    else parent[k] = value
    next[top] = parent
  }
  return next
}
vi.stubGlobal('fetch', vi.fn(async (input: string | URL, init?: RequestInit) => {
  const url = new URL(String(input))
  const method = init?.method ?? 'GET'
  const byId = url.pathname.match(/^\/admin\/identities\/([^/]+)$/)
  if (url.pathname === '/admin/identities' && method === 'GET') {
    let all = [...h.identities.values()]
    const org = url.searchParams.get('organization_id')
    if (org) all = all.filter((i) => i.organization_id === org)
    const identifier = url.searchParams.get('credentials_identifier')
    if (identifier) all = all.filter((i) => (i.traits as { email: string }).email === identifier)
    return json(all)
  }
  if (byId && method === 'GET') {
    await pause()
    const held = h.identities.get(byId[1])
    return held ? json(structuredClone(held)) : json({ error: { code: 404 } }, 404)
  }
  if (byId && method === 'PATCH') {
    await pause()
    const held = h.identities.get(byId[1])
    if (!held) return json({ error: { code: 404 } }, 404)
    const body = JSON.parse(String(init!.body))
    h.patches.push({ id: byId[1], body })
    const next = applyPatch(held, body)
    h.identities.set(byId[1], next)
    return json(next)
  }
  return json({ error: 'unexpected' }, 500)
}))

const store = await import('../../../services/organisation-store.js')
const { kratosService } = await import('../../../services/kratos.service.js')

function person(id: string, email: string, extra: Record<string, unknown> = {}) {
  return { id, schema_id: 'default', state: 'active', traits: { email }, metadata_admin: null, organization_id: null, ...extra }
}
const flush = () => new Promise((r) => setTimeout(r, 0))

beforeEach(async () => {
  h.kv.clear()
  h.hashes.clear()
  h.identities.clear()
  h.patches = []
  h.delayMs = 0
  h.invalidateBundle.mockClear()
  kratosService.invalidateGroupsCache()
  h.identities.set(BOB, person(BOB, 'bob@example.com'))
  h.identities.set(ALICE, person(ALICE, 'alice@example.com', { metadata_admin: { groups: ['ops'] } }))
})

async function seedOrganisations() {
  for (const [id, name, tenant] of [[ACME, 'Acme', 'acme'], [GLOBEX, 'Globex', 'globex'], [INITECH, 'Initech', 'initech']]) {
    await store.applyOrganisations([{ id, name, tenant }])
  }
}

describe('which store', () => {
  it('is kratos without a database URL, and needs nothing else to be configured', () => {
    expect(store.organisationStoreMode()).toBe('kratos')
    expect(store.organisationStoreConfigured()).toBe(true)
    expect(store.membershipRowsKept()).toBe(false)
  })
})

describe('the registry (Redis)', () => {
  it('creates, lists, reads, renames and deletes an organisation', async () => {
    const created = await store.createOrganisation({ name: 'Acme Corp', tenant: 'acme-corp', attributes: { tier: 'gold' } })
    expect(created).toMatchObject({ name: 'Acme Corp', tenant: 'acme-corp', attributes: { tier: 'gold' } })
    expect(created.id).toMatch(/^[0-9a-f-]{36}$/)

    expect(await store.allOrganisations()).toEqual([created])
    expect(await store.organisationsById([created.id, 'not-held'])).toEqual([created])

    const renamed = await store.updateOrganisation(created.id, { name: 'Acme Inc' })
    expect(renamed).toEqual({ ...created, name: 'Acme Inc' })

    await store.deleteOrganisation(created.id)
    expect(await store.allOrganisations()).toEqual([])
    await expect(store.deleteOrganisation(created.id)).rejects.toBeInstanceOf(store.OrganisationNotFoundError)
    await expect(store.updateOrganisation(created.id, { name: 'x' })).rejects.toBeInstanceOf(store.OrganisationNotFoundError)
  })

  it('keeps entitlements as a whole set, and gives the engine only what is on', async () => {
    await seedOrganisations()
    await store.setDeployments(ACME, [{ application: 'fleet', enabled: true }, { application: 'billing', enabled: false }])
    await store.setDeployments(GLOBEX, [{ application: 'fleet', enabled: true }])
    expect(await store.deploymentsOf(ACME)).toEqual([
      { application: 'billing', enabled: false },
      { application: 'fleet', enabled: true },
    ])
    expect(await store.allEntitlements()).toEqual(new Map([[ACME, ['fleet']], [GLOBEX, ['fleet']]]))

    await store.setDeployments(ACME, [])
    expect(await store.allEntitlements()).toEqual(new Map([[GLOBEX, ['fleet']]]))
  })

  it('refuses to delete an organisation somebody still belongs to, and says how many', async () => {
    await seedOrganisations()
    await store.addMember(ACME, BOB, 'member')
    const refused = await store.deleteOrganisation(ACME).catch((e: unknown) => e)
    expect(refused).toBeInstanceOf(store.OrganisationInUseError)
    expect((refused as { members: number }).members).toBe(1)
    expect(await store.organisationsById([ACME])).toHaveLength(1)
  })

  it('answers a Redis outage as unavailable, never as "no organisations"', async () => {
    const hgetall = h.redis.hgetall
    h.redis.hgetall = async () => { throw new Error('ECONNREFUSED') }
    await expect(store.allOrganisations()).rejects.toBeInstanceOf(store.OrganisationStoreUnavailableError)
    h.redis.hgetall = hgetall
  })
})

describe('membership on the identity', () => {
  beforeEach(seedOrganisations)

  it('makes the first organisation primary and lists the next, in one write each', async () => {
    await store.addMember(ACME, BOB, 'member')
    await store.addMember(GLOBEX, BOB, 'member')
    const bob = h.identities.get(BOB)!
    expect(bob.organization_id).toBe(ACME)
    expect(bob.metadata_admin).toEqual({ organizations: [GLOBEX] })
    expect(await store.organisationsForSubject(BOB)).toEqual([ACME, GLOBEX])
    // One PATCH per change, each naming only what changed.
    expect(h.patches.map((p) => p.body.map((o) => o.path))).toEqual([['/organization_id'], ['/metadata_admin']])
  })

  it('is idempotent: joining twice writes nothing the second time', async () => {
    await store.addMember(ACME, BOB, 'member')
    const writes = h.patches.length
    await store.addMember(ACME, BOB, 'member')
    expect(h.patches.length).toBe(writes)
  })

  it('refuses to add somebody to an organisation the registry does not hold', async () => {
    await expect(store.addMember('99999999-9999-4999-8999-999999999999', BOB, 'member')).rejects.toBeInstanceOf(
      store.OrganisationNotFoundError,
    )
    expect(h.identities.get(BOB)!.organization_id).toBeNull()
  })

  it('removing the primary promotes the next one, and removing the last clears it', async () => {
    await store.addMember(ACME, BOB, 'member')
    await store.addMember(GLOBEX, BOB, 'member')
    await store.removeMember(ACME, BOB)
    expect(h.identities.get(BOB)!.organization_id).toBe(GLOBEX)
    expect(await store.organisationsForSubject(BOB)).toEqual([GLOBEX])
    await store.removeMember(GLOBEX, BOB)
    expect(h.identities.get(BOB)!.organization_id).toBeNull()
    expect(await store.organisationsForSubject(BOB)).toEqual([])
  })

  it('keeps org-scoped roles on the identity, and a role can be given up without leaving', async () => {
    await store.addMember(ACME, BOB, 'member')
    await store.addMember(ACME, BOB, 'billing-contact')
    expect(await store.membersOf(ACME)).toEqual([
      { subjectId: BOB, role: 'billing-contact' },
      { subjectId: BOB, role: 'member' },
    ])
    await store.removeMember(ACME, BOB, 'billing-contact')
    expect(await store.membersOf(ACME)).toEqual([{ subjectId: BOB, role: 'member' }])
    expect(h.identities.get(BOB)!.metadata_admin).not.toHaveProperty('organization_roles')
  })

  it('sets exactly a set, keeping the primary when it stays, and refuses only NEW unknown organisations', async () => {
    await store.addMember(ACME, BOB, 'member')
    await store.setMemberships(BOB, [GLOBEX, ACME, INITECH])
    expect(h.identities.get(BOB)!.organization_id).toBe(ACME)
    expect(await store.organisationsForSubject(BOB)).toEqual([ACME, GLOBEX, INITECH])

    // Somebody already in an organisation that predates the registry can still be edited.
    const LEGACY = '44444444-4444-4444-8444-444444444444'
    h.identities.set(ALICE, { ...h.identities.get(ALICE)!, organization_id: LEGACY })
    await store.setMemberships(ALICE, [LEGACY, ACME])
    expect(await store.organisationsForSubject(ALICE)).toEqual([LEGACY, ACME])
    await expect(store.setMemberships(ALICE, ['55555555-5555-4555-8555-555555555555'])).rejects.toBeInstanceOf(
      store.OrganisationNotFoundError,
    )

    await store.removeMemberEverywhere(BOB)
    expect(await store.organisationsForSubject(BOB)).toEqual([])
  })

  it('answers a subject that no longer exists as belonging nowhere', async () => {
    expect(await store.organisationsForSubject('dddddddd-dddd-4ddd-8ddd-dddddddddddd')).toEqual([])
  })
})

describe('isolation between organisations', () => {
  beforeEach(seedOrganisations)

  it('lists each organisation’s own members only, and a change in one leaves the other alone', async () => {
    await store.addMember(ACME, BOB, 'member')
    await store.addMember(GLOBEX, ALICE, 'member')
    await store.addMember(GLOBEX, BOB, 'member')

    expect((await store.membersOf(ACME)).map((m) => m.subjectId)).toEqual([BOB])
    expect((await store.membersOf(GLOBEX)).map((m) => m.subjectId).sort()).toEqual([ALICE, BOB].sort())
    expect(await store.membersOf(INITECH)).toEqual([])

    await store.removeMember(GLOBEX, ALICE)
    expect((await store.membersOf(ACME)).map((m) => m.subjectId)).toEqual([BOB])
    expect(await store.organisationsForSubject(ALICE)).toEqual([])
    expect(await store.organisationsForSubject(BOB)).toEqual([ACME, GLOBEX])
  })
})

describe('no lost update', () => {
  beforeEach(seedOrganisations)

  it('two organisations added at once to one person both land', async () => {
    h.delayMs = 5
    await Promise.all([store.addMember(ACME, BOB, 'member'), store.addMember(GLOBEX, BOB, 'member'), store.addMember(INITECH, BOB, 'member')])
    expect((await store.organisationsForSubject(BOB)).sort()).toEqual([ACME, GLOBEX, INITECH].sort())
  })

  it('a group edit and a membership change at once both land', async () => {
    h.delayMs = 5
    await Promise.all([
      kratosService.updateUserGroups('alice@example.com', ['ops', 'billing']),
      store.addMember(ACME, ALICE, 'member'),
      store.addMember(GLOBEX, ALICE, 'member'),
    ])
    const alice = h.identities.get(ALICE)!
    expect((alice.metadata_admin as { groups: string[] }).groups).toEqual(['ops', 'billing'])
    expect((await store.organisationsForSubject(ALICE)).sort()).toEqual([ACME, GLOBEX].sort())
  })
})

describe('groups live on the identity, once', () => {
  it('reads one person’s groups fresh, and a change is not written a second time by the store', async () => {
    expect(await store.groupsForSubjects([ALICE, BOB])).toEqual(new Map([[ALICE, ['ops']]]))
    await store.applyGroupChange(ALICE, ['ops'], ['billing'])
    expect(h.patches).toEqual([])
  })

  it('gives the policy bundle everybody’s groups keyed by subject', async () => {
    // Bob holds no group: no base `users` group is invented for him.
    expect(await store.allGroupMemberships()).toEqual(new Map([[ALICE, ['ops']]]))
    expect(await store.membersOfGroup('ops')).toEqual([ALICE])
  })
})

describe('after every write', () => {
  beforeEach(seedOrganisations)

  it('drops the directory cache and pushes to OPAL', async () => {
    const invalidate = vi.spyOn(kratosService, 'invalidateGroupsCache')
    h.invalidateBundle.mockClear()
    await store.addMember(ACME, BOB, 'member')
    await flush()
    expect(invalidate).toHaveBeenCalled()
    expect(h.invalidateBundle).toHaveBeenCalledWith(
      'organisation.member_added',
      { type: 'organization', id: ACME },
      undefined,
      undefined,
      { audit: false },
    )
  })

  it('a reader right after a membership change sees it (no stale directory)', async () => {
    expect(await store.membersOf(ACME)).toEqual([])
    await store.addMember(ACME, BOB, 'member')
    expect((await store.membersOf(ACME)).map((m) => m.subjectId)).toEqual([BOB])
  })
})

describe('the OPAL bindings are the same shape', () => {
  beforeEach(seedOrganisations)

  it('user_organizations and user_organization_primary come from the identity, keyed by email', async () => {
    await store.addMember(ACME, BOB, 'member')
    await store.addMember(GLOBEX, BOB, 'member')
    const { RbacService } = await vi.importActual<typeof import('../../../services/rbac.service.js')>(
      '../../../services/rbac.service.js',
    )
    const bindings = await new RbacService().getBindingsFromKratos()
    expect(bindings.user_organizations).toEqual({ 'bob@example.com': [GLOBEX, ACME] })
    expect(bindings.user_organization_primary).toEqual({ 'bob@example.com': ACME })
    expect(bindings.group_membership).toEqual({ 'bob@example.com': [], 'alice@example.com': ['ops'] })
  })
})

describe('moving from postgres', () => {
  it('an export document applies into the kratos store: records, deployments, members and groups', async () => {
    await store.applyOrganisations([
      {
        id: ACME,
        name: 'Acme',
        tenant: 'acme',
        deployments: [{ application: 'fleet', enabled: true }],
        members: [{ subjectId: BOB, role: 'member' }, { subjectId: BOB, role: 'admin-contact' }, { subjectId: ALICE, role: 'member' }],
      },
    ])
    await store.setGroupsOf(BOB, ['devs'])

    expect(await store.allOrganisations()).toEqual([{ id: ACME, name: 'Acme', tenant: 'acme', attributes: {} }])
    expect(await store.allEntitlements()).toEqual(new Map([[ACME, ['fleet']]]))
    expect(await store.membersOf(ACME)).toEqual([
      { subjectId: ALICE, role: 'member' },
      { subjectId: BOB, role: 'admin-contact' },
      { subjectId: BOB, role: 'member' },
    ])
    expect((await store.groupsForSubjects([BOB])).get(BOB)).toEqual(['devs'])

    // Replayable: the same input again changes nothing on any identity.
    const writes = h.patches.length
    await store.applyOrganisations([
      {
        id: ACME,
        name: 'Acme',
        tenant: 'acme',
        deployments: [{ application: 'fleet', enabled: true }],
        members: [{ subjectId: BOB, role: 'member' }, { subjectId: BOB, role: 'admin-contact' }, { subjectId: ALICE, role: 'member' }],
      },
    ])
    expect(h.patches.length).toBe(writes)
  })
})

describe('the org admin screens, on the kratos store', () => {
  beforeEach(seedOrganisations)

  it('joining from the console is one write to the identity, and leaving another — no second copy', async () => {
    const { joinOrganisation, leaveOrganisation } = await import('../../../services/org-membership.service.js')
    await joinOrganisation(h.identities.get(BOB) as never, ACME)
    await joinOrganisation(h.identities.get(BOB) as never, GLOBEX)
    expect(h.patches).toHaveLength(2)
    await leaveOrganisation(h.identities.get(BOB) as never, ACME)
    expect(h.patches).toHaveLength(3)
    expect(await store.organisationsForSubject(BOB)).toEqual([GLOBEX])
  })

  it('an organisation’s member list includes the people for whom it is not the primary one', async () => {
    const { identitiesInOrganisation } = await import('../../../services/org-membership.service.js')
    await store.addMember(ACME, BOB, 'member')
    await store.addMember(GLOBEX, BOB, 'member')
    await store.addMember(GLOBEX, ALICE, 'member')
    const members = await identitiesInOrganisation(GLOBEX)
    expect(members.map((i) => i.id).sort()).toEqual([ALICE, BOB].sort())
    expect((await identitiesInOrganisation(INITECH)).map((i) => i.id)).toEqual([])
  })
})
