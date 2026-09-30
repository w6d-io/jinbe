import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

// Roles and route maps go to OPA as ONE entry each (dst_path /roles, /route_map) instead of one per
// service, so the manifest never changes when a service is added. OPA must end up holding exactly the
// data it held with the per-service entries.

const store = vi.hoisted(() => ({
  services: [] as string[],
  roles: {} as Record<string, Record<string, string[]> | null>,
  routeMaps: {} as Record<string, { rules: unknown[] } | null>,
  groups: {} as Record<string, unknown>,
  fail: false,
  groupsFail: false,
}))
const getBindingsFromKratos = vi.hoisted(() => vi.fn())
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
    getGroups: async () => {
      if (store.groupsFail) throw new Error('redis down')
      return structuredClone(store.groups)
    },
    getOrgServiceMap: async () => ({}),
    getOrgAdminMap: async () => ({}),
    getOrgAdminMapAsStored: async () => ({}),
  },
}))
// The other data sources, so a whole-manifest refresh can run: their content does not matter here.
vi.mock('../../../services/org-grants.repository.js', () => ({ orgGrantsRepository: { getAll: async () => ({}) } }))
vi.mock('../../../sites/login-store.js', () => ({ siteLoginStore: { getAll: async () => ({}) } }))
vi.mock('../../../second-factor/settings.js', () => ({ getSecondFactorGroups: async () => ['super_admins'] }))
vi.mock('../../../services/api-clients.js', () => ({ apiClientsDataset: async () => ({}) }))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { getBindingsFromKratos } }))
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
  store.groupsFail = false
  store.groups = { super_admins: { global: ['super_admin'] }, kuma_viewers: { kuma: ['viewer'] } }
  getBindingsFromKratos.mockReset().mockImplementation(async () => ({
    emails: {},
    group_membership: { 'root@example.com': ['super_admins'] },
    user_organizations: {},
    user_organization_primary: {},
  }))
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
      'bindings', 'opal/roles', 'opal/route_maps', 'opal/org_service_map', 'opal/org_admin_map',
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

describe('data.bindings is written in one PUT — never a window without bindings.groups', () => {
  /** OPAL's fetch: a non-2xx answer skips that entry's write (opal_client/data/updater.py). */
  async function fetchWithStatus(routes: Map<string, Handler>, path: string): Promise<{ status: number; body: unknown }> {
    const handler = routes.get(path.replace(/^\/api\/admin\/rbac/, ''))
    if (!handler) throw new Error(`no route for ${path}`)
    let status = 200
    let body: unknown
    const reply = { status(s: number) { status = s; return this }, send(b: unknown) { body = b; return this } } as unknown as FastifyReply
    try {
      await handler({ params: {}, log: { error: vi.fn() } } as unknown as FastifyRequest, reply)
    } catch {
      status = 500
    }
    return { status, body }
  }

  /**
   * One OPAL refresh as the 0.7.12 client stores it: every entry fetched, then one PUT per entry in
   * manifest order. `probe` runs after every PUT — the state a decision taken at that instant sees.
   */
  async function refresh(entries: Array<{ url: string; dst_path: string }>, routes: Map<string, Handler>, data: Record<string, unknown>, probe: () => void) {
    const fetched = await Promise.all(entries.map(async (e) => ({ e, ...(await fetchWithStatus(routes, new URL(e.url).pathname)) })))
    for (const { e, status, body } of fetched) {
      if (status >= 300) continue
      put(data, e.dst_path, structuredClone(body))
      probe()
    }
  }

  const groupsOf = (data: Record<string, unknown>) => (data.bindings as { groups?: unknown } | undefined)?.groups

  it('no entry\'s dst_path equals, contains or sits under another\'s (a parent PUT wipes its child)', async () => {
    const paths = (await buildOpalDatasourceEntries()).map((e) => e.dst_path)
    const within = (a: string, b: string) => a === b || b.startsWith(a.endsWith('/') ? a : `${a}/`)
    for (const [i, a] of paths.entries()) {
      for (const [j, b] of paths.entries()) {
        if (i !== j) expect(within(a, b), `${a} vs ${b}`).toBe(false)
      }
    }
  })

  it('the /bindings payload carries groups, from the same store /opal/groups reads', async () => {
    const { routes } = await mount()
    const { status, body } = await fetchWithStatus(routes, '/api/admin/rbac/bindings')
    expect(status).toBe(200)
    expect(body).toEqual({
      emails: {},
      group_membership: { 'root@example.com': ['super_admins'] },
      user_organizations: {},
      user_organization_primary: {},
      groups: store.groups,
    })
    expect((await fetchWithStatus(routes, '/api/admin/rbac/opal/groups')).body).toEqual(store.groups)
  })

  it('answers 503 (no data) when Kratos fails, or when the group store fails', async () => {
    const { routes } = await mount()
    getBindingsFromKratos.mockRejectedValueOnce(new Error('kratos down'))
    let res = await fetchWithStatus(routes, '/api/admin/rbac/bindings')
    expect(res.status).toBe(503)
    expect(res.body).not.toHaveProperty('group_membership')
    expect(res.body).not.toHaveProperty('groups')

    store.groupsFail = true
    res = await fetchWithStatus(routes, '/api/admin/rbac/bindings')
    expect(res.status).toBe(503)
    expect(res.body).not.toHaveProperty('group_membership')
    // the route older manifests still poll: 503, not a thrown 500
    expect((await fetchWithStatus(routes, '/api/admin/rbac/opal/groups')).status).toBe(503)
  })

  it('refreshing with the manifest: data.bindings.groups is present after every PUT', async () => {
    const { routes } = await mount()
    const entries = await buildOpalDatasourceEntries()
    const data: Record<string, unknown> = {}
    await refresh(entries, routes, data, () => {})   // cold start
    store.groups = { ...store.groups, pilots: { stairfleet1: ['pilot'] } }
    const seen: unknown[] = []
    await refresh(entries, routes, data, () => seen.push(groupsOf(data)))
    expect(seen.length).toBe(entries.length)
    for (const g of seen) expect(g).toBeDefined()
    expect(groupsOf(data)).toEqual(store.groups)
  })

  it('the manifest this replaces (/bindings then /bindings/groups) DID open that window — the probe sees it', async () => {
    const { routes } = await mount()
    const legacy = [
      { url: 'http://auth-jinbe:8080/api/admin/rbac/bindings', dst_path: '/bindings' },
      { url: 'http://auth-jinbe:8080/api/admin/rbac/opal/groups', dst_path: '/bindings/groups' },
    ]
    // what /bindings answered before this change: the Kratos part only, no groups
    const routesOld = new Map(routes)
    routesOld.set('/bindings', async (_req, reply) => reply.send(await getBindingsFromKratos()))
    const data: Record<string, unknown> = { bindings: { groups: store.groups } }
    const seen: unknown[] = []
    await refresh(legacy, routesOld, data, () => seen.push(groupsOf(data)))
    expect(seen[0]).toBeUndefined()

    // and a failing groups fetch left it wiped for the whole refresh period
    store.groupsFail = true
    await refresh(legacy, routesOld, data, () => {})
    expect(groupsOf(data)).toBeUndefined()
  })

  it('a group store failure keeps the last good data.bindings whole — super_admins stay resolvable', async () => {
    const { routes } = await mount()
    const entries = await buildOpalDatasourceEntries()
    const data: Record<string, unknown> = {}
    await refresh(entries, routes, data, () => {})
    const before = structuredClone(data.bindings)
    store.groupsFail = true
    await refresh(entries, routes, data, () => expect(groupsOf(data)).toBeDefined())
    expect(data.bindings).toEqual(before)
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
