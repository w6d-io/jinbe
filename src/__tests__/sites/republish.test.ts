import { describe, it, expect, beforeEach, vi } from 'vitest'
import { ACME, payrollSite } from './fixtures.js'

// The reseed half of --apply: every applied site's permissions written again from its applied
// version — with explicit roles, even when the stored intent predates the refusal of wildcards.

const s = vi.hoisted(() => ({
  records: [] as Array<{ site: { name: string; state: string }; applied?: { version: number } }>,
  versions: new Map<string, unknown>(),
  published: [] as Array<{ name: string; perms: { roles: Record<string, string[]>; orgRoles: Record<string, string[]> } }>,
}))

vi.mock('../../sites/repository.js', () => ({
  sitesRepository: {
    list: vi.fn(async () => s.records),
    version: vi.fn(async (name: string, v: number) => s.versions.get(`${name}@${v}`) ?? null),
  },
}))
vi.mock('../../sites/platform.js', async () => ({ loadPlatform: vi.fn(async () => (await import('./fixtures.js')).platform) }))
vi.mock('../../sites/publish.js', () => ({
  publishPermissions: vi.fn(async (name: string, perms: never) => { s.published.push({ name, perms }) }),
}))
vi.mock('../../sites/login-store.js', () => ({ siteLoginStore: { set: vi.fn(async () => {}) } }))
vi.mock('../../sites/checks.js', () => ({ pinnedHostsOf: () => new Map() }))

import { republishAppliedSites, renderAppliedSites } from '../../sites/republish.js'

beforeEach(() => {
  s.records = []
  s.versions.clear()
  s.published = []
})

describe('republishAppliedSites', () => {
  it('publishes each applied site with explicit roles: a stored * becomes the permissions it stood for', async () => {
    const legacy = payrollSite({ roles: { admin: ['*'], editor: ['payslips:*'], viewer: ['payslips:read'] } })
    s.records = [{ site: { name: 'payroll', state: 'active' }, applied: { version: 2 } }, { site: { name: 'draft', state: 'active' } }]
    s.versions.set('payroll@2', { site: legacy })
    const out = await republishAppliedSites({ email: 'jinbe (bootstrap apply)' })
    expect(out).toEqual({ published: ['payroll'], failed: [] })
    expect(s.published[0].perms.roles).toEqual({ admin: ['payslips:create', 'payslips:read'], editor: ['payslips:create', 'payslips:read'], viewer: ['payslips:read'] })
    expect(Object.values(s.published[0].perms.roles).flat()).not.toContain('*')
    expect(s.published[0].perms.orgRoles).toEqual({ editors: ['payslips:create', 'payslips:read'] })
  })

  it('one site failing does not stop the others, and is reported', async () => {
    s.records = [{ site: { name: 'payroll', state: 'active' }, applied: { version: 1 } }, { site: { name: 'wiki', state: 'active' }, applied: { version: 3 } }]
    s.versions.set('payroll@1', { site: payrollSite() })
    const out = await republishAppliedSites({ email: 'x' })
    expect(out.published).toEqual(['payroll'])
    expect(out.failed).toEqual([{ site: 'wiki', error: 'applied version 3 is gone' }])
  })

  it('renderAppliedSites is the same model the plan reads', async () => {
    s.records = [{ site: { name: 'payroll', state: 'active' }, applied: { version: 1 } }]
    s.versions.set('payroll@1', { site: payrollSite() })
    const { models } = await renderAppliedSites()
    expect(Object.keys(models[0].rendered.orgServiceMap)).toEqual([ACME])
  })
})
