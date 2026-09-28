import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { KratosService } from '../../services/kratos.service.js'
import { invalidateCachedIdentity } from '../../controllers/webhook.controller.js'
import { configureCache } from '../../cache/swr.js'

/**
 * The cached Kratos reads against a fake Kratos: a change made through jinbe or announced by the
 * webhook is visible on the very next read; a change made behind jinbe within the fresh window; an
 * organisation's member list is only ever that organisation's; the kill switch turns it all off.
 */

interface Ident {
  id: string
  traits: { email: string; name?: string }
  state: string
  schema_id: string
  metadata_admin?: { groups?: string[] }
  organization_id?: string | null
  credentials?: Record<string, unknown>
}

const kratos = new Map<string, Ident>()
const calls: string[] = []

function reply(body: unknown, status = 200) {
  return { ok: status < 400, status, statusText: String(status), json: async () => body, text: async () => '', headers: { get: () => null } }
}

const strip = (i: Ident, withCreds: boolean) => {
  const { credentials, ...rest } = i
  return withCreds ? { ...rest, credentials } : rest
}

const fetchMock = vi.fn(async (url: string, init: RequestInit = {}) => {
  const u = new URL(url)
  const method = init.method ?? 'GET'
  calls.push(`${method} ${u.pathname}${u.search}`)
  const withCreds = u.searchParams.getAll('include_credential').length > 0
  const one = u.pathname.match(/^\/admin\/identities\/([^/]+)$/)
  if (u.pathname === '/admin/identities' && method === 'GET') {
    let list = [...kratos.values()]
    const ids = u.searchParams.getAll('ids')
    if (ids.length) list = list.filter((i) => ids.includes(i.id))
    const org = u.searchParams.get('organization_id')
    if (org) list = list.filter((i) => i.organization_id === org)
    const ident = u.searchParams.get('credentials_identifier')
    if (ident) list = list.filter((i) => i.traits.email === ident)
    return reply(list.map((i) => strip(i, withCreds)))
  }
  if (one && method === 'GET') {
    const i = kratos.get(one[1])
    return i ? reply(strip(i, withCreds)) : reply({ error: 'not found' }, 404)
  }
  if (one && (method === 'PUT' || method === 'PATCH')) {
    const i = kratos.get(one[1])!
    const body = JSON.parse(String(init.body))
    if (method === 'PUT') Object.assign(i, { traits: body.traits, metadata_admin: body.metadata_admin, state: body.state })
    else for (const p of body) (i as unknown as Record<string, unknown>)[p.path.slice(1)] = p.value
    return reply(strip(i, false))
  }
  const cred = u.pathname.match(/^\/admin\/identities\/([^/]+)\/credentials\/([^/]+)$/)
  if (cred && method === 'DELETE') {
    delete kratos.get(cred[1])!.credentials?.[cred[2]]
    return reply(undefined, 204)
  }
  return reply({ error: 'unexpected' }, 500)
})

const totp = () => ({ totp: { config: { totp_url: 'otpauth://totp/secret' } } })

function seed() {
  kratos.clear()
  const add = (id: string, email: string, org: string | null, groups: string[], credentials: Record<string, unknown> = {}) =>
    kratos.set(id, { id, traits: { email, name: email.split('@')[0] }, state: 'active', schema_id: 'default', metadata_admin: { groups }, organization_id: org, credentials })
  add('u-alice', 'alice@a.test', 'org-a', ['users'], totp())
  add('u-bob', 'bob@a.test', 'org-a', ['users'])
  add('u-carol', 'carol@b.test', 'org-b', ['org-admins'], totp())
}

let service: KratosService

beforeEach(() => {
  global.fetch = fetchMock as unknown as typeof fetch
  calls.length = 0
  seed()
  service = new KratosService()
})
afterEach(() => {
  vi.useRealTimers()
  configureCache({ enabled: true, disabled: [] })
})

const walks = () => calls.filter((c) => c.startsWith('GET /admin/identities?page_size=500')).length

describe('the directory walk', () => {
  it('is walked once and shared by every reader', async () => {
    await service.getAllIdentitiesWithBindings()
    await service.searchIdentities('a')
    await service.getAllIdentitiesWithGroups()
    expect(walks()).toBe(1)
  })

  it('a group change made through jinbe is visible on the very next read', async () => {
    expect((await service.getAllIdentitiesWithBindings()).get('bob@a.test')?.groups).toEqual(['users'])
    await service.updateUserGroups('bob@a.test', ['users', 'admins'])
    expect((await service.getAllIdentitiesWithBindings()).get('bob@a.test')?.groups).toEqual(['users', 'admins'])
  })

  it('a profile change announced by the Kratos webhook is visible on the very next read', async () => {
    await service.getAllIdentitiesWithBindings()
    kratos.get('u-bob')!.traits.name = 'Robert'
    invalidateCachedIdentity('settings', 'profile', 'u-bob')
    expect((await service.getAllIdentitiesWithBindings()).get('bob@a.test')?.name).toBe('Robert')
  })

  it('a registration announced by the webhook shows the newcomer at once', async () => {
    await service.getAllIdentitiesWithBindings()
    kratos.set('u-dan', { id: 'u-dan', traits: { email: 'dan@a.test' }, state: 'active', schema_id: 'default' })
    invalidateCachedIdentity('registration', 'password', 'u-dan')
    expect((await service.getAllIdentitiesWithBindings()).has('dan@a.test')).toBe(true)
  })

  it('a change made behind jinbe (no event) shows within the fresh window, and at once to the OPAL feed bound', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    await service.getAllIdentitiesWithBindings()
    kratos.get('u-bob')!.metadata_admin = { groups: ['users', 'ops'] }
    vi.setSystemTime(Date.now() + 6_000)
    // A display read may still get the snapshot (fresh 15s) …
    expect((await service.getAllIdentitiesWithBindings()).get('bob@a.test')?.groups).toEqual(['users'])
    // … the authorization feed never takes one older than 5s.
    expect((await service.getAllIdentitiesWithBindings({ maxAgeMs: 5_000 })).get('bob@a.test')?.groups).toEqual(['users', 'ops'])
  })

  it('kill switch: every read walks Kratos', async () => {
    configureCache({ enabled: false })
    await service.getAllIdentitiesWithBindings()
    await service.getAllIdentitiesWithBindings()
    expect(walks()).toBe(2)
  })
})

describe('second factors for display', () => {
  it('are read for many identities in ONE Kratos call, then from cache', async () => {
    const mfa = await service.mfaByIds(['u-alice', 'u-bob', 'u-carol'])
    expect(mfa.get('u-alice')).toEqual(['totp'])
    expect(mfa.get('u-bob')).toEqual([])
    const listCalls = calls.filter((c) => c.startsWith('GET /admin/identities?'))
    expect(listCalls).toHaveLength(1)
    expect(listCalls[0]).toContain('ids=u-alice')
    await service.mfaByIds(['u-alice', 'u-bob'])
    expect(calls.filter((c) => c.startsWith('GET /admin/identities?'))).toHaveLength(1)
  })

  it('a removed second factor is visible immediately', async () => {
    await service.mfaByIds(['u-alice'])
    await service.deleteSecondFactor('u-alice', 'totp')
    expect((await service.mfaByIds(['u-alice'])).get('u-alice')).toEqual([])
  })

  it('an enrolment announced by the webhook is visible immediately', async () => {
    await service.mfaByIds(['u-bob'])
    kratos.get('u-bob')!.credentials = totp()
    invalidateCachedIdentity('settings', 'totp', 'u-bob')
    expect((await service.mfaByIds(['u-bob'])).get('u-bob')).toEqual(['totp'])
  })

  it('never caches the credential itself', async () => {
    await service.mfaByIds(['u-alice'])
    const { MemoryCacheStore } = await import('../../cache/store.js')
    // The engine's memory store is private; what matters is what it was handed.
    const spy = vi.spyOn(MemoryCacheStore.prototype, 'writeUnlessInvalidated')
    await service.mfaByIds(['u-carol'])
    const written = spy.mock.calls.map((c) => c[1]).join('\n')
    expect(written).toContain('totp')
    expect(written).not.toContain('otpauth')
    spy.mockRestore()
  })
})

describe('identities by id', () => {
  it('one batched call; missing ids absent; an older Kratos ignoring `ids` still answers correctly', async () => {
    const found = await service.getIdentitiesByIds(['u-bob', 'u-carol', 'u-ghost'])
    expect([...found.keys()].sort()).toEqual(['u-bob', 'u-carol'])
    expect(calls.filter((c) => c.includes('ids='))).toHaveLength(1)
  })

  it('an update through jinbe drops the cached identity', async () => {
    expect((await service.getIdentityCached('u-bob')).traits.name).toBe('bob')
    await service.updateIdentity('u-bob', { traits: { email: 'bob@a.test', name: 'Bobby' } } as never)
    expect((await service.getIdentityCached('u-bob')).traits.name).toBe('Bobby')
  })
})

describe('cross-tenant isolation', () => {
  it("an organisation's member list is only ever that organisation's, whoever asked first", async () => {
    const a = await service.listIdentitiesByOrganizationCached('org-a')
    const b = await service.listIdentitiesByOrganizationCached('org-b')
    expect(a.map((i) => i.id).sort()).toEqual(['u-alice', 'u-bob'])
    expect(b.map((i) => i.id)).toEqual(['u-carol'])
    // And the identifier filter is part of the key: a search in org-a never answers from org-a's full list.
    const searched = await service.listIdentitiesByOrganizationCached('org-a', { credentialsIdentifier: 'bob@a.test' })
    expect(searched.map((i) => i.id)).toEqual(['u-bob'])
  })

  it('moving somebody between organisations shows in both lists at once', async () => {
    await service.listIdentitiesByOrganizationCached('org-a')
    await service.listIdentitiesByOrganizationCached('org-b')
    await service.patchIdentity('u-bob', [{ op: 'replace', path: '/organization_id', value: 'org-b' }])
    expect((await service.listIdentitiesByOrganizationCached('org-a')).map((i) => i.id)).toEqual(['u-alice'])
    expect((await service.listIdentitiesByOrganizationCached('org-b')).map((i) => i.id).sort()).toEqual(['u-bob', 'u-carol'])
  })

  it('cached identities never carry credentials', async () => {
    const i = await service.getIdentityCached('u-alice')
    expect(i.credentials).toBeUndefined()
  })
})
