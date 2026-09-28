import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

const { held, queryOpa } = vi.hoisted(() => {
  const held = new Map<string, { groups: string[]; roles: string[]; permissions: string[]; orgs: string[] }>()
  const queryOpa = vi.fn(async (rule: string, input: Record<string, unknown>) => {
    await new Promise((r) => setTimeout(r, 2))
    if (rule === 'rbac/user_info') {
      const h = held.get(String(input.email))
      return { groups: h?.groups ?? [], roles: h?.roles ?? [], permissions: h?.permissions ?? [] }
    }
    if (rule === 'rbac/delegation/manageable_orgs') return held.get(String((input.actor as { email: string }).email))?.orgs ?? []
    return undefined
  })
  return { held, queryOpa }
})
vi.mock('../../services/opa-client.js', () => ({ queryOpa }))

import { rights, rightsForDisplay, manageableOrgs, invalidateAuthz, clearAuthzCache, AUTHZ_PROPAGATION_MS } from '../../authz/opa.js'
import { configureCache } from '../../cache/swr.js'

/**
 * The OPA answer cache: one query per question however many ask at once, answers keyed by the
 * question (so one caller's never answers another's), dropped on every RBAC change and again once OPA
 * has loaded it, and nothing cached at all behind the kill switch.
 */

beforeEach(() => {
  clearAuthzCache()
  held.clear()
  held.set('admin-a@x.test', { groups: ['org-a-admins'], roles: ['org_admin'], permissions: ['users:read'], orgs: ['org-a'] })
  held.set('admin-b@x.test', { groups: ['org-b-admins'], roles: ['org_admin'], permissions: ['users:read'], orgs: ['org-b'] })
})
afterEach(() => {
  vi.useRealTimers()
  configureCache({ enabled: true, disabled: [] })
})

describe('authorization answers', () => {
  it('a console opening fires dozens of guarded requests: OPA is asked once', async () => {
    await Promise.all(Array.from({ length: 49 }, () => rights('admin-a@x.test')))
    expect(queryOpa).toHaveBeenCalledTimes(1)
  })

  it("one org admin's cached answer never answers another's question", async () => {
    expect(await manageableOrgs('admin-a@x.test')).toEqual(['org-a'])
    expect(await manageableOrgs('admin-b@x.test')).toEqual(['org-b'])
    expect(await manageableOrgs('admin-a@x.test')).toEqual(['org-a'])
    expect((await rights('admin-b@x.test')).groups).toEqual(['org-b-admins'])
  })

  it('a group removal is honoured on the next request after the RBAC change', async () => {
    expect((await rights('admin-a@x.test')).permissions).toEqual(['users:read'])
    held.get('admin-a@x.test')!.permissions = []
    invalidateAuthz()
    expect((await rights('admin-a@x.test')).permissions).toEqual([])
  })

  it('an answer read while OPA was still loading the change is dropped once OPA has it', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'], shouldAdvanceTime: true })
    await rights('admin-a@x.test')
    invalidateAuthz()
    // OPA has not loaded the change yet: the re-asked answer is still the old one …
    expect((await rights('admin-a@x.test')).permissions).toEqual(['users:read'])
    held.get('admin-a@x.test')!.permissions = []
    // … and it is dropped again after the propagation delay, well inside the 5s TTL.
    await vi.advanceTimersByTimeAsync(AUTHZ_PROPAGATION_MS + 10)
    expect((await rights('admin-a@x.test')).permissions).toEqual([])
  })

  it('the display copy (a users page, one question per row) outlives the decision TTL but not an RBAC change', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    await rightsForDisplay('admin-a@x.test')
    vi.setSystemTime(Date.now() + 10_000) // past the 5s decision TTL
    await rightsForDisplay('admin-a@x.test')
    expect(queryOpa).toHaveBeenCalledTimes(1)
    held.get('admin-a@x.test')!.groups = []
    invalidateAuthz()
    expect((await rightsForDisplay('admin-a@x.test')).groups).toEqual([])
  })

  it('a failure is not cached', async () => {
    queryOpa.mockRejectedValueOnce(new Error('down'))
    await expect(rights('admin-a@x.test')).rejects.toThrow()
    expect((await rights('admin-a@x.test')).groups).toEqual(['org-a-admins'])
  })

  it('kill switch: every question goes to OPA', async () => {
    configureCache({ enabled: false })
    await rights('admin-a@x.test')
    await rights('admin-a@x.test')
    expect(queryOpa).toHaveBeenCalledTimes(2)
  })
})
