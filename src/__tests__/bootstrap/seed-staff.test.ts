import { describe, it, expect, beforeEach, vi } from 'vitest'

const store = vi.hoisted(() => ({
  services: new Set<string>(),
  roles: new Map<string, Record<string, string[]>>(),
  groups: new Map<string, Record<string, string[]>>(),
  groupMeta: new Map<string, Record<string, unknown>>(),
  etagInvalidated: 0,
}))

vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    serviceExists: vi.fn(async (n: string) => store.services.has(n)),
    addService: vi.fn(async (n: string) => { store.services.add(n) }),
    getRoles: vi.fn(async (svc: string) => store.roles.get(svc) ?? null),
    setRoles: vi.fn(async (svc: string, r: Record<string, string[]>) => { store.roles.set(svc, r) }),
    getGroup: vi.fn(async (n: string) => store.groups.get(n) ?? null),
    getGroups: vi.fn(async () => Object.fromEntries(store.groups)),
    setGroup: vi.fn(async (n: string, g: Record<string, string[]>) => { store.groups.set(n, g) }),
    setGroupMetadata: vi.fn(async (n: string, m: Record<string, unknown>) => { store.groupMeta.set(n, m) }),
    invalidateBundleEtag: vi.fn(async () => { store.etagInvalidated++; return 'etag' }),
  },
}))

import { seedStaffRoles, unshadowStaffRoles } from '../../bootstrap/seed-staff.js'
import { ROLES } from '../../policy/roles.js'

const logger = { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() } as never

beforeEach(() => {
  store.services = new Set(['jinbe', 'global'])
  store.roles = new Map([['global', { super_admin: ['*'], admin: ['*'] }]])
  store.groups = new Map([['super_admins', { global: ['super_admin'] }], ['platform-admins', { global: ['admin'] }]])
  store.groupMeta = new Map()
  store.etagInvalidated = 0
})

describe('seedStaffRoles', () => {
  it('writes every staff role into roles.global and creates the empty staff groups, flagged system', async () => {
    const out = await seedStaffRoles(logger)
    const global = store.roles.get('global')!
    expect(global.support).toEqual([...new Set(ROLES.support.permissions)])
    expect(global.viewer).toEqual([...ROLES.viewer.permissions])
    // Other global roles are the owner's to retire, not the seed's.
    expect(global.admin).toEqual(['*'])
    expect(out.groups).toEqual(['staff-viewers', 'staff-support', 'staff-ops', 'staff-developers', 'staff-auditors', 'staff-security'])
    expect(store.groups.get('staff-ops')).toEqual({ global: ['ops'] })
    expect(store.groupMeta.get('staff-ops')).toMatchObject({ system: true })
    expect(out.conflicts).toEqual([])
    expect(store.etagInvalidated).toBe(1)
  })

  it('is idempotent: a second run changes nothing', async () => {
    await seedStaffRoles(logger)
    const out = await seedStaffRoles(logger)
    expect(out).toEqual({ roles: [], groups: [], conflicts: [] })
    expect(store.etagInvalidated).toBe(1)
  })

  it('puts a runtime edit of a staff role back to the code', async () => {
    await seedStaffRoles(logger)
    store.roles.get('global')!.viewer = ['*']
    const out = await seedStaffRoles(logger)
    expect(out.roles).toEqual(['viewer'])
    expect(store.roles.get('global')!.viewer).toEqual([...ROLES.viewer.permissions])
  })

  it('never takes over a group of that name bound to something else, and never deletes one', async () => {
    store.groups.set('staff-support', { jinbe: ['support'] })
    const out = await seedStaffRoles(logger)
    expect(store.groups.get('staff-support')).toEqual({ jinbe: ['support'] })
    expect(out.conflicts).toEqual(['staff-support exists without global:support'])
    expect(store.groups.has('platform-admins')).toBe(true)
  })
})

// The policy merges roles by name across scopes: jinbe.support (the old support seed, holding
// users:update_email) went to every staff-support member (e2e R-S5).
describe('unshadowStaffRoles', () => {
  beforeEach(() => {
    store.roles.set('jinbe', { admin: ['*'], support: ['users:read', 'users:update_email'], viewer: ['databases:read'] })
    store.groups.set('support', { jinbe: ['support'] })
    store.groups.set('jinbe-viewer', { jinbe: ['viewer'], kuma: ['viewer'] })
  })

  it('renames a jinbe role named like a staff role, and moves the groups binding it', async () => {
    expect(await unshadowStaffRoles(logger)).toEqual({ support: 'legacy_support', viewer: 'legacy_viewer' })
    expect(store.roles.get('jinbe')).toEqual({ admin: ['*'], legacy_support: ['users:read', 'users:update_email'], legacy_viewer: ['databases:read'] })
    expect(store.groups.get('support')).toEqual({ jinbe: ['legacy_support'] })
    // Another service's role of that name is not jinbe's to rename.
    expect(store.groups.get('jinbe-viewer')).toEqual({ jinbe: ['legacy_viewer'], kuma: ['viewer'] })
    expect(store.etagInvalidated).toBe(1)
  })

  it('runs on every staff seed, and a second run changes nothing', async () => {
    await seedStaffRoles(logger)
    expect(store.roles.get('jinbe')!.support).toBeUndefined()
    expect(await unshadowStaffRoles(logger)).toEqual({})
  })

  it('never overwrites an existing legacy_ role', async () => {
    store.roles.set('jinbe', { support: ['users:update_email'], legacy_support: ['users:read'] })
    expect(await unshadowStaffRoles(logger)).toEqual({ support: 'legacy_support_2' })
    expect(store.roles.get('jinbe')).toEqual({ legacy_support: ['users:read'], legacy_support_2: ['users:update_email'] })
  })
})
