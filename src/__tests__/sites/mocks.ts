import type { OathkeeperRule, RouteMap } from '../../services/redis-rbac.repository.js'

/** Just enough of ioredis for the Sites store. */
export class InlineRedisMock {
  hashes = new Map<string, Map<string, string>>()
  strings = new Map<string, string>()
  lists = new Map<string, string[]>()
  async hget(k: string, f: string) { return this.hashes.get(k)?.get(f) ?? null }
  async hset(k: string, f: string, v: string) {
    if (!this.hashes.has(k)) this.hashes.set(k, new Map())
    this.hashes.get(k)!.set(f, v)
    return 1
  }
  async hdel(k: string, f: string) { return this.hashes.get(k)?.delete(f) ? 1 : 0 }
  async hgetall(k: string) { return Object.fromEntries(this.hashes.get(k)?.entries() ?? []) }
  async get(k: string) { return this.strings.get(k) ?? null }
  async set(k: string, v: string) { this.strings.set(k, v); return 'OK' }
  async del(k: string) { return this.strings.delete(k) || this.lists.delete(k) ? 1 : 0 }
  async rpush(k: string, v: string) {
    if (!this.lists.has(k)) this.lists.set(k, [])
    this.lists.get(k)!.push(v)
    return this.lists.get(k)!.length
  }
  async lrange(k: string, a: number, b: number) {
    const l = this.lists.get(k) ?? []
    return l.slice(a, b === -1 ? undefined : b + 1)
  }
  clear() {
    this.hashes.clear()
    this.strings.clear()
    this.lists.clear()
  }
}

/** The RBAC keys the Sites apply path writes, in memory, with a write log for ordering assertions. */
export function makeRbacStore() {
  const s = {
    services: new Set<string>(['jinbe', 'kuma']),
    routeMaps: {} as Record<string, RouteMap>,
    roles: {} as Record<string, Record<string, string[]>>,
    groups: { admins: { kuma: ['admin'] }, super_admins: { global: ['super_admin'] } } as Record<string, Record<string, string[]>>,
    groupMeta: {} as Record<string, unknown>,
    serviceMeta: {} as Record<string, unknown>,
    orgMap: {} as Record<string, string[]>,
    accessRules: [] as OathkeeperRule[],
    log: [] as string[],
  }
  const repo = {
    getServices: async () => [...s.services],
    serviceExists: async (n: string) => s.services.has(n),
    addService: async (n: string) => { s.log.push(`addService:${n}`); s.services.add(n) },
    removeService: async (n: string) => { s.log.push(`removeService:${n}`); s.services.delete(n) },
    getRouteMap: async (n: string) => s.routeMaps[n] ?? null,
    setRouteMap: async (n: string, m: RouteMap) => { s.log.push(`setRouteMap:${n}`); s.routeMaps[n] = m },
    deleteRouteMap: async (n: string) => { s.log.push(`deleteRouteMap:${n}`); return delete s.routeMaps[n] },
    getRoles: async (n: string) => s.roles[n] ?? null,
    setRoles: async (n: string, r: Record<string, string[]>) => { s.log.push(`setRoles:${n}`); s.roles[n] = r },
    deleteRoles: async (n: string) => { s.log.push(`deleteRoles:${n}`); return delete s.roles[n] },
    getGroups: async () => structuredClone(s.groups),
    getGroup: async (g: string) => s.groups[g] ?? null,
    setGroup: async (g: string, d: Record<string, string[]>) => { s.log.push(`setGroup:${g}`); s.groups[g] = d },
    deleteGroup: async (g: string) => { s.log.push(`deleteGroup:${g}`); return delete s.groups[g] },
    setGroupMetadata: async (g: string, m: unknown) => { s.groupMeta[g] = m },
    deleteGroupMetadata: async (g: string) => { delete s.groupMeta[g] },
    getServiceMetadata: async (n: string) => s.serviceMeta[n] ?? null,
    setServiceMetadata: async (n: string, m: unknown) => { s.serviceMeta[n] = m },
    deleteServiceMetadata: async (n: string) => { delete s.serviceMeta[n] },
    getOrgServiceMap: async () => structuredClone(s.orgMap),
    setOrgServiceMapping: async (o: string, svcs: string[]) => {
      s.log.push(`setOrgServiceMapping:${o}`)
      if (svcs.length === 0) delete s.orgMap[o]
      else s.orgMap[o] = svcs
    },
    getAccessRules: async () => s.accessRules,
  }
  const reset = () => {
    s.services = new Set(['jinbe', 'kuma'])
    s.routeMaps = {}
    s.roles = {}
    s.groups = { admins: { kuma: ['admin'] }, super_admins: { global: ['super_admin'] } }
    s.groupMeta = {}
    s.serviceMeta = {}
    s.orgMap = {}
    s.accessRules = []
    s.log = []
  }
  return { s, repo, reset }
}

export interface FakeGatekitState {
  compile: (patterns: Array<{ id: string }>) => unknown
  overlap: (body: unknown) => unknown
  status: number
  calls: Array<{ path: string; body: Record<string, unknown> }>
}

/** A `fetch` answering like gatekit (GK-1 contract), recording every call. */
export function fakeGatekit(g: FakeGatekitState) {
  return async (url: URL | string, init: { body: string }) => {
    const path = new URL(url.toString()).pathname
    const body = JSON.parse(init.body)
    g.calls.push({ path, body })
    if (g.status !== 200) return new Response('down', { status: g.status })
    const answer =
      path === '/compile' ? g.compile(body.patterns)
      : path === '/overlap' ? g.overlap(body)
      : path === '/match' ? { matched: [body.rules[0]?.id].filter(Boolean), verdict: 'one' }
      : path === '/render' ? { value: 'rendered', bytes: 8 }
      : {}
    return new Response(JSON.stringify(answer), { status: 200, headers: { 'content-type': 'application/json' } })
  }
}
