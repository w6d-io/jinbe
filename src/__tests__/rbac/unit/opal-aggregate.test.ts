import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

// Roles and route maps go to OPA as ONE entry each (dst_path /roles, /route_map) instead of one per
// service, so the manifest never changes when a service is added. OPA must end up holding exactly the
// data it held with the per-service entries.

const store = vi.hoisted(() => ({
  services: [] as string[],
  roles: {} as Record<string, Record<string, string[]> | null>,
  routeMaps: {} as Record<string, { rules: unknown[] } | null>,
  fail: false,
}))
const mirrorOpalFetch = vi.hoisted(() => vi.fn())

vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getServices: async () => [...store.services],
    getRoles: async (svc: string) => {
      if (store.fail) throw new Error('redis down')
      return store.roles[svc] ?? null
    },
    getRouteMap: async (svc: string) => {
      if (store.fail) throw new Error('redis down')
      return store.routeMaps[svc] ?? null
    },
  },
}))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { getBindingsFromKratos: vi.fn() } }))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: {}, KratosApiError: class extends Error {} }))
vi.mock('../../../home/runtime.js', () => ({ mirrorOpalFetch }))
vi.mock('../../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../config/env.js')>()
  return { ...real, env: { ...real.env, OPAL_CLIENT_TOKEN: 't'.repeat(64), JINBE_INTERNAL_URL: 'http://auth-jinbe:8080', OPAL_DATA_REFRESH_SECONDS: 60 } }
})

import { rbacOpalRoutes } from '../../../routes/rbac-opal.routes.js'
import { buildOpalDatasourceEntries, opalEntryName } from '../../../services/opal-datasource.js'

type Handler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
type Hook = (request: FastifyRequest, reply: FastifyReply) => Promise<void>

async function mount() {
  const routes = new Map<string, Handler>()
  const hooks: Record<string, Hook> = {}
  const fastify = {
    get: (path: string, a: unknown, b?: unknown) => { routes.set(path, (typeof a === 'function' ? a : b) as Handler) },
    addHook: (name: string, fn: Hook) => { hooks[name] = fn },
  } as unknown as FastifyInstance
  await rbacOpalRoutes(fastify)
  return { routes, hooks }
}

/** Calls a route the way OPAL fetches it: by the entry's URL path, params matched by hand. */
async function fetchEntry(routes: Map<string, Handler>, path: string): Promise<unknown> {
  const sub = path.replace(/^\/api\/admin\/rbac/, '')
  let handler = routes.get(sub)
  let params: Record<string, string> = {}
  if (!handler) {
    const [, kind, service] = sub.match(/^\/opal\/(roles|route_map)\/([^/]+)$/) ?? []
    handler = routes.get(`/opal/${kind}/:service`)
    params = { service }
  }
  if (!handler) throw new Error(`no route for ${path}`)
  let body: unknown
  const reply = { status() { return this }, send(b: unknown) { body = b; return this } } as unknown as FastifyReply
  await handler({ params } as unknown as FastifyRequest, reply)
  return body
}

/** OPA's data API as OPAL writes it: PUT at dst_path replaces that whole subtree. */
function put(data: Record<string, unknown>, dstPath: string, value: unknown) {
  const parts = dstPath.split('/').filter(Boolean)
  let node = data
  for (const p of parts.slice(0, -1)) node = (node[p] ??= {}) as Record<string, unknown>
  node[parts[parts.length - 1]] = value
}

/** The per-service layout the manifest used to carry, entry for entry. */
async function legacyEntries(): Promise<Array<{ url: string; dst_path: string }>> {
  const base = 'http://auth-jinbe:8080/api/admin/rbac'
  const out = [{ url: `${base}/opal/roles/global`, dst_path: '/roles/global' }]
  for (const svc of store.services) {
    out.push({ url: `${base}/opal/roles/${svc}`, dst_path: `/roles/${svc}` })
    if (store.routeMaps[svc]) out.push({ url: `${base}/opal/route_map/${svc}`, dst_path: `/route_map/${svc}` })
  }
  return out
}

async function opaData(entries: Array<{ url: string; dst_path: string }>, routes: Map<string, Handler>) {
  const data: Record<string, unknown> = {}
  for (const e of entries.filter((x) => x.dst_path.startsWith('/roles') || x.dst_path.startsWith('/route_map'))) {
    put(data, e.dst_path, await fetchEntry(routes, new URL(e.url).pathname))
  }
  return { roles: data.roles, route_map: data.route_map }
}

beforeEach(() => {
  mirrorOpalFetch.mockClear()
  store.fail = false
  store.services = ['kuma', 'stairfleet1', 'empty']
  store.roles = {
    global: { super_admin: ['*'] },
    kuma: { viewer: ['sites:read'], editor: ['sites:read', 'sites:write'] },
    stairfleet1: { pilot: ['fleet:fly'] },
    empty: null,
  }
  store.routeMaps = {
    kuma: { rules: [{ method: 'GET', path: '/sites', permission: 'sites:read' }] },
    stairfleet1: { rules: [{ method: 'POST', path: '/fly/{org}', permission: 'fleet:fly', org_param: 'org' }] },
    empty: null,
  }
})

describe('OPAL roles / route maps as aggregate entries', () => {
  it('OPA holds the same data.roles.<svc> and data.route_map.<svc> as with the per-service entries', async () => {
    const { routes } = await mount()
    const before = await opaData(await legacyEntries(), routes)
    const after = await opaData(await buildOpalDatasourceEntries(), routes)
    expect(after).toEqual(before)
    // spelled out, so a change on both sides at once cannot pass unnoticed
    expect(after.roles).toEqual({
      global: { super_admin: ['*'] },
      kuma: { viewer: ['sites:read'], editor: ['sites:read', 'sites:write'] },
      stairfleet1: { pilot: ['fleet:fly'] },
      empty: {},
    })
    expect(Object.keys(after.route_map as object).sort()).toEqual(['kuma', 'stairfleet1'])
  })

  it('carries global roles even when "global" is also listed as a service, once', async () => {
    store.services = ['global', 'kuma']
    const { routes } = await mount()
    expect(await opaData(await buildOpalDatasourceEntries(), routes)).toEqual(await opaData(await legacyEntries(), routes))
  })

  it('the manifest does not change when a service is added or removed', async () => {
    const before = await buildOpalDatasourceEntries()
    store.services = [...store.services, 'wallets']
    store.roles.wallets = { treasurer: ['wallets:pay'] }
    expect(await buildOpalDatasourceEntries()).toEqual(before)
    store.services = ['kuma']
    expect(await buildOpalDatasourceEntries()).toEqual(before)
    expect(before.map((e) => opalEntryName(e.url))).toEqual([
      'bindings', 'opal/groups', 'opal/roles', 'opal/route_maps', 'opal/org_service_map', 'opal/org_admin_map',
      'opal/org_grants', 'opal/site_login', 'opal/second_factor', 'opal/api_clients',
    ])
    for (const e of before) expect(e.periodic_update_interval).toBe(60)
  })

  it('a store error fails the whole fetch — never a partial subtree that would replace what OPA holds', async () => {
    const { routes } = await mount()
    store.fail = true
    await expect(fetchEntry(routes, '/api/admin/rbac/opal/roles')).rejects.toThrow('redis down')
    await expect(fetchEntry(routes, '/api/admin/rbac/opal/route_maps')).rejects.toThrow('redis down')
  })
})

describe('recordDatasourceFetch → Home mirror', () => {
  const fetched = async (url: string, statusCode = 200) => {
    const { hooks } = await mount()
    await hooks.onResponse({ url, routeOptions: { url } } as unknown as FastifyRequest, { statusCode, elapsedTime: 3 } as unknown as FastifyReply)
  }

  it('mirrors a data fetch under its entry name', async () => {
    await fetched('/api/admin/rbac/opal/roles')
    expect(mirrorOpalFetch).toHaveBeenCalledWith('opal/roles')
  })

  it('does not count the manifest fetch (read once per client connect) as policy data', async () => {
    await fetched('/api/admin/rbac/opal-datasource')
    expect(mirrorOpalFetch).not.toHaveBeenCalled()
  })

  it('does not mirror a failed fetch', async () => {
    await fetched('/api/admin/rbac/opal/roles', 500)
    expect(mirrorOpalFetch).not.toHaveBeenCalled()
  })
})
