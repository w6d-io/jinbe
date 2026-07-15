import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { RouteRule } from '../../bootstrap/types.js'

const store = vi.hoisted(() => ({ routeMap: null as { rules: RouteRule[] } | null }))

vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getRouteMap: vi.fn(async () => store.routeMap),
    setRouteMap: vi.fn(async (_svc: string, rm: { rules: RouteRule[] }) => { store.routeMap = rm }),
  },
}))

import { mergeJinbeRouteMap } from '../../bootstrap/merge-route-map.js'

const logger = { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() } as never
const P = '/api/organizations/:organizationId/users'

beforeEach(() => {
  store.routeMap = null
  vi.clearAllMocks()
})

describe('mergeJinbeRouteMap', () => {
  it('seeds all variants for a path that does not exist yet', async () => {
    const { added } = await mergeJinbeRouteMap(
      [{ method: 'GET', path: P, permission: 'admin:read' }, { method: 'GET', path: P, permission: 'org:manage_users' }],
      logger,
    )
    expect(added).toBe(2)
    expect(store.routeMap!.rules).toHaveLength(2)
  })

  it('adds a NEW built-in permission variant alongside an existing built-in one', async () => {
    store.routeMap = { rules: [{ method: 'GET', path: P, permission: 'admin:read' }] }
    const { added } = await mergeJinbeRouteMap(
      [{ method: 'GET', path: P, permission: 'admin:read' }, { method: 'GET', path: P, permission: 'org:manage_users' }],
      logger,
    )
    expect(added).toBe(1)
    const perms = store.routeMap!.rules.map((r) => r.permission)
    expect(perms).toEqual(['admin:read', 'org:manage_users'])
  })

  it('does NOT resurrect a built-in default when the operator tightened the path in place (F1)', async () => {
    // Operator replaced admin:read with a stricter custom permission.
    store.routeMap = { rules: [{ method: 'GET', path: P, permission: 'admin:superread' }] }
    const { added } = await mergeJinbeRouteMap(
      [{ method: 'GET', path: P, permission: 'admin:read' }, { method: 'GET', path: P, permission: 'org:manage_users' }],
      logger,
    )
    expect(added).toBe(0)
    // The stricter override stands alone — the weaker built-in is not re-added.
    expect(store.routeMap!.rules).toEqual([{ method: 'GET', path: P, permission: 'admin:superread' }])
  })

  it('is idempotent when all built-in variants are already present', async () => {
    store.routeMap = { rules: [
      { method: 'GET', path: P, permission: 'admin:read' },
      { method: 'GET', path: P, permission: 'org:manage_users' },
    ] }
    const { added } = await mergeJinbeRouteMap(
      [{ method: 'GET', path: P, permission: 'admin:read' }, { method: 'GET', path: P, permission: 'org:manage_users' }],
      logger,
    )
    expect(added).toBe(0)
  })

  it('never rewrites or drops an operator-added custom route on another path', async () => {
    store.routeMap = { rules: [{ method: 'GET', path: '/api/custom', permission: 'custom:read' }] }
    await mergeJinbeRouteMap([{ method: 'GET', path: P, permission: 'org:manage_users' }], logger)
    expect(store.routeMap!.rules).toContainEqual({ method: 'GET', path: '/api/custom', permission: 'custom:read' })
  })
})
