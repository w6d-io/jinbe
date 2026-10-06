import { describe, it, expect, beforeEach, vi } from 'vitest'
import { ACME, payrollSite } from './fixtures.js'

// The reseed half of --apply: every applied site's permissions written again from its applied
// version — with explicit roles, even when the stored intent predates the refusal of wildcards.

const s = vi.hoisted(() => ({
  records: [] as Array<{ site: { name: string; state: string }; applied?: { version: number } }>,
  versions: new Map<string, unknown>(),
  published: [] as Array<{ name: string; perms: { roles: Record<string, string[]>; orgRoles: Record<string, string[]> } }>,
  saved: [] as Array<{ site: { name: string; roles: unknown }; opts: { by: string; note?: string; ifMatch?: string } }>,
  applied: [] as Array<{ name: string; applied: unknown }>,
  audits: [] as Array<{ verb: string; name: string; details?: Record<string, unknown> }>,
}))

vi.mock('../../sites/repository.js', () => ({
  sitesRepository: {
    list: vi.fn(async () => s.records),
    version: vi.fn(async (name: string, v: number) => s.versions.get(`${name}@${v}`) ?? null),
    save: vi.fn(async (site: { name: string; roles: unknown }, opts: { by: string; note?: string; ifMatch?: string }) => {
      s.saved.push({ site, opts })
      const rec = s.records.find((r) => r.site.name === site.name) as { version?: number } | undefined
      return { site, version: (rec?.version ?? 0) + 1 }
    }),
    setApplied: vi.fn(async (name: string, applied: unknown) => { s.applied.push({ name, applied }) }),
  },
}))
vi.mock('../../sites/audit.js', () => ({
  auditSite: vi.fn((verb: string, name: string, _actor: unknown, _summary: string, details?: Record<string, unknown>) => { s.audits.push({ verb, name, details }) }),
}))
vi.mock('../../sites/platform.js', async () => ({ loadPlatform: vi.fn(async () => (await import('./fixtures.js')).platform) }))
vi.mock('../../sites/publish.js', () => ({
  publishPermissions: vi.fn(async (name: string, perms: never) => { s.published.push({ name, perms }) }),
}))
vi.mock('../../sites/login-store.js', () => ({ siteLoginStore: { set: vi.fn(async () => {}) } }))
vi.mock('../../sites/checks.js', () => ({ pinnedHostsOf: () => new Map() }))

import { EXPLICIT_ROLES_NOTE, persistExplicitRoles, republishAppliedSites, renderAppliedSites, sitesWithWildcards } from '../../sites/republish.js'

beforeEach(() => {
  s.records = []
  s.versions.clear()
  s.published = []
  s.saved = []
  s.applied = []
  s.audits = []
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

  it('a version applied before the organizations switch existed keeps its org roles, orgs and owner role', async () => {
    const legacy = payrollSite({ organizations: undefined, groups: { platform: {}, orgGrantable: { 'payroll-admin': { label: 'Admins', roles: ['admin'] } } } })
    s.records = [{ site: { name: 'payroll', state: 'active' }, applied: { version: 1 } }]
    s.versions.set('payroll@1', { site: legacy })
    await republishAppliedSites({ email: 'x' })
    const perms = s.published[0].perms as unknown as { orgRoles: object; orgServiceMap: object; ownerRole: string | null }
    expect(perms.orgRoles).toEqual({ admin: ['payslips:create', 'payslips:read'] })
    expect(Object.keys(perms.orgServiceMap)).toEqual([ACME])
    expect(perms.ownerRole).toBe('admin')
    // And the stored intent is made explicit with the wildcards, so its next edit saves.
    s.records = [{ site: legacy, applied: { version: 1 } } as never]
    expect(sitesWithWildcards(s.records as never)).toEqual(['payroll'])
  })

  it('renderAppliedSites is the same model the plan reads', async () => {
    s.records = [{ site: { name: 'payroll', state: 'active' }, applied: { version: 1 } }]
    s.versions.set('payroll@1', { site: payrollSite() })
    const { models } = await renderAppliedSites()
    expect(Object.keys(models[0].rendered.orgServiceMap)).toEqual([ACME])
  })
})

describe('stored wildcards made explicit (the first edit after the release saves)', () => {
  const legacy = () => payrollSite({ roles: { admin: ['*'], editor: ['payslips:read', 'payslips:create'], viewer: ['payslips:read'] } })

  it('saves a new version with the explicit roles, noted and audited, and marks it applied in place of the old one', async () => {
    s.records = [
      { site: legacy(), version: 4, etag: 'e4', applied: { version: 4, at: 'x', by: 'y', rules: [] } } as never,
      { site: payrollSite({ name: 'clean' }), version: 2, etag: 'e2', applied: { version: 2 } } as never,
    ]
    expect(sitesWithWildcards(s.records as never)).toEqual(['payroll'])
    const made = await persistExplicitRoles({ email: 'jinbe (bootstrap apply)' })
    expect(made).toEqual([{ site: 'payroll', from: 4, to: 5, applied: true }])
    expect(s.saved).toHaveLength(1)
    expect(s.saved[0].site.roles).toEqual({ admin: ['payslips:create', 'payslips:read'], editor: ['payslips:read', 'payslips:create'], viewer: ['payslips:read'] })
    expect(s.saved[0].opts).toEqual({ by: 'jinbe (bootstrap apply)', note: EXPLICIT_ROLES_NOTE, ifMatch: 'e4' })
    expect(EXPLICIT_ROLES_NOTE).toBe("roles made explicit by the authz release (was '*')")
    // Same rules, new version number: nothing published changes.
    expect(s.applied).toEqual([{ name: 'payroll', applied: { version: 5, at: 'x', by: 'y', rules: [] } }])
    expect(s.audits).toEqual([{ verb: 'roles_made_explicit', name: 'payroll', details: { from: 4, to: 5, applied: true } }])
  })

  it('a site with unapplied saves gets its new version without moving what is applied; idempotent', async () => {
    s.records = [{ site: legacy(), version: 6, etag: 'e6', applied: { version: 4 } } as never]
    expect(await persistExplicitRoles({ email: 'jinbe (bootstrap)' })).toEqual([{ site: 'payroll', from: 6, to: 7, applied: false }])
    expect(s.applied).toEqual([])
    s.records = [{ site: s.saved[0].site, version: 7, etag: 'e7', applied: { version: 4 } } as never]
    expect(await persistExplicitRoles({ email: 'jinbe (bootstrap)' })).toEqual([])
  })
})
