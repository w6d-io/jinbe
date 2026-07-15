import { describe, it, expect, beforeEach, vi } from 'vitest'

// In-memory RBAC repository stub — models roles, groups, and service existence.
const store = vi.hoisted(() => ({
  services: new Set<string>(),
  roles: new Map<string, Record<string, string[]>>(),
  groups: new Map<string, Record<string, string[]>>(),
  etagInvalidated: 0,
}))

vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    serviceExists: vi.fn(async (n: string) => store.services.has(n)),
    getRoles: vi.fn(async (svc: string) => store.roles.get(svc) ?? null),
    setRoles: vi.fn(async (svc: string, r: Record<string, string[]>) => { store.roles.set(svc, r) }),
    getGroup: vi.fn(async (n: string) => store.groups.get(n) ?? null),
    setGroup: vi.fn(async (n: string, g: Record<string, string[]>) => { store.groups.set(n, g) }),
    invalidateBundleEtag: vi.fn(async () => { store.etagInvalidated++; return 'etag' }),
  },
}))

import { seedDelegation } from '../../bootstrap/seed-delegation.js'

const logger = { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() } as never

beforeEach(() => {
  store.services = new Set(['kuma', 'jinbe'])
  store.roles = new Map([
    ['kuma', { admin: ['*'], viewer: ['read'] }],
    ['jinbe', { admin: ['*'], viewer: ['databases:list', 'databases:read'] }],
  ])
  store.groups = new Map()
  store.etagInvalidated = 0
  vi.clearAllMocks()
})

describe('seedDelegation', () => {
  it('seeds org_admin role + <svc>-org-admins/-viewers groups for each delegated service', async () => {
    const { seeded } = await seedDelegation(logger)

    // org_admin holds the fine-grained user-mgmt perms UNION the service viewer
    // perms (so containment lets it grant <svc>-viewers).
    expect(store.roles.get('kuma')!['org_admin']).toEqual(
      expect.arrayContaining(['org:manage_users', 'users:read', 'users:create', 'users:assign_group', 'read'])
    )
    expect(store.roles.get('jinbe')!['org_admin']).toEqual(
      expect.arrayContaining(['org:manage_users', 'databases:read'])
    )
    // NOT admin:* / * — org_admin is strictly fine-grained.
    expect(store.roles.get('kuma')!['org_admin']).not.toContain('*')
    expect(store.roles.get('kuma')!['org_admin']).not.toContain('admin:read')

    expect(store.groups.get('kuma-org-admins')).toEqual({ kuma: ['org_admin'] })
    expect(store.groups.get('kuma-viewers')).toEqual({ kuma: ['viewer'] })
    expect(store.groups.get('jinbe-org-admins')).toEqual({ jinbe: ['org_admin'] })
    expect(seeded.length).toBe(6) // 2 roles + 4 groups
  })

  it('preserves existing service roles (additive, not a replace)', async () => {
    await seedDelegation(logger)
    expect(store.roles.get('kuma')!['admin']).toEqual(['*'])
    expect(store.roles.get('kuma')!['viewer']).toEqual(['read'])
  })

  it('is idempotent — a second run adds nothing and does not overwrite', async () => {
    await seedDelegation(logger)
    // Tamper with the seeded role to prove re-run does not clobber it.
    store.roles.get('kuma')!['org_admin'] = ['custom']
    const { seeded } = await seedDelegation(logger)
    expect(seeded).toEqual([])
    expect(store.roles.get('kuma')!['org_admin']).toEqual(['custom'])
  })

  it('skips a service that does not exist', async () => {
    store.services = new Set(['kuma']) // jinbe absent
    const { seeded } = await seedDelegation(logger)
    expect(seeded.some((s) => s.includes('jinbe'))).toBe(false)
    expect(store.groups.has('jinbe-org-admins')).toBe(false)
    expect(logger.warn).toHaveBeenCalled()
  })
})
