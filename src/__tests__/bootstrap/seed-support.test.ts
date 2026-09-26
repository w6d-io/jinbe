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
    getRoles: vi.fn(async (svc: string) => store.roles.get(svc) ?? null),
    setRoles: vi.fn(async (svc: string, r: Record<string, string[]>) => { store.roles.set(svc, r) }),
    getGroup: vi.fn(async (n: string) => store.groups.get(n) ?? null),
    setGroup: vi.fn(async (n: string, g: Record<string, string[]>) => { store.groups.set(n, g) }),
    setGroupMetadata: vi.fn(async (n: string, m: Record<string, unknown>) => { store.groupMeta.set(n, m) }),
    invalidateBundleEtag: vi.fn(async () => { store.etagInvalidated++; return 'etag' }),
  },
}))

import { seedSupport, SUPPORT_PERMISSIONS } from '../../bootstrap/seed-support.js'

const logger = { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() } as never

beforeEach(() => {
  store.services = new Set(['jinbe'])
  store.roles = new Map([['jinbe', { admin: ['*'], viewer: ['databases:read'] }]])
  store.groups = new Map()
  store.groupMeta = new Map()
  store.etagInvalidated = 0
})

describe('seedSupport', () => {
  it('seeds role jinbe.support and group support = {jinbe: [support]}', async () => {
    const { seeded } = await seedSupport(logger)
    expect(seeded).toEqual(['role:jinbe.support', 'group:support'])
    expect(store.roles.get('jinbe')!.support).toEqual([
      'users:read', 'users:update', 'users:update_email', 'sessions:read', 'sessions:revoke', 'users:recovery', 'users:send_login_link',
    ])
    expect(store.groups.get('support')).toEqual({ jinbe: ['support'] })
    // Other roles survive the write.
    expect(store.roles.get('jinbe')!.admin).toEqual(['*'])
    expect(store.etagInvalidated).toBe(1)
  })

  it('grants no administration, no deletion, no creation and no group assignment', () => {
    for (const p of ['*', 'admin:read', 'admin:write', 'users:delete', 'users:create', 'users:assign_group']) {
      expect(SUPPORT_PERMISSIONS).not.toContain(p)
    }
  })

  it('is idempotent: a second run does nothing', async () => {
    await seedSupport(logger)
    const { seeded } = await seedSupport(logger)
    expect(seeded).toEqual([])
    expect(store.etagInvalidated).toBe(1)
  })

  it('never overwrites an operator\'s support role or group', async () => {
    store.roles.get('jinbe')!.support = ['users:read']
    store.groups.set('support', { jinbe: ['support'], kuma: ['viewer'] })
    const { seeded } = await seedSupport(logger)
    expect(seeded).toEqual([])
    expect(store.roles.get('jinbe')!.support).toEqual(['users:read'])
    expect(store.groups.get('support')).toEqual({ jinbe: ['support'], kuma: ['viewer'] })
  })

  it('skips without a jinbe service', async () => {
    store.services = new Set()
    expect((await seedSupport(logger)).seeded).toEqual([])
    expect(store.groups.size).toBe(0)
  })
})
