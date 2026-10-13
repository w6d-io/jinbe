import type { Access, Gate, Site } from './schemas.js'
import { sitesRepository, type SiteRecord } from './repository.js'
import { loadZones } from './platform.js'
import { placeHost } from './host.js'
import { prefixContains } from './nesting.js'
import { organizationsOn } from './organizations.js'
import { listRequests } from './requests.js'
import { draftChangesNothing, statusOf, type SiteStatus } from './sites.service.js'
import { sitesConfig } from './config.js'
import { siteError } from './checks.js'

/**
 * Sites by address (Sites redesign, phase 1): the sites grouped by the host they are saved on, each
 * host showing every service mounted on it — its path, the backend it reaches, who may reach it.
 * A reading of the site records only: nothing is merged, saved or published here, and every site keeps
 * its own editor. Draft-only sites (never saved) are listed under the host their draft names.
 *
 * A service is an `api` when every gate its routes and catch-all use (deny excepted) answers refusals
 * as JSON (`errors: 'api'`): a browser is never sent to a sign-in page there. Anything else is a `page`.
 */

export interface AccessSummary {
  /** Some path is open without signing in. */
  public: boolean
  /** Some path is open to any signed-in account. */
  signedIn: boolean
  /** The permissions its routes and catch-all ask for, sorted. */
  permissions: string[]
  /** Organization API keys may come in (organizations on, a gate taking OAuth2 tokens). */
  orgKeys: boolean
}

export interface HostService {
  site: string
  displayName: string
  pathPrefix: string | null
  /** The service on the same host whose prefix encloses this one most closely (the longest prefix wins). */
  parent: string | null
  upstream: { service: string; namespace: string; port: number; stripPath?: string; path?: string } | null
  kind: 'page' | 'api'
  access: AccessSummary
  status: SiteStatus
  /** An unsaved draft is waiting. */
  draft: boolean
  /** An apply request is waiting for a super admin. */
  pendingRequest: boolean
  /** Other sites (any host) reaching the same backend Service. */
  sharedBackendWith: string[]
}

export interface HostEntry {
  host: string
  zone: string | null
  services: HostService[]
  counts: { services: number; live: number; drafts: number; pendingRequests: number }
}

export interface HostRoute {
  id: string
  methods: string[]
  path: string
  access: Access
  /** The path the backend receives for this route (strip_path removed, upstream.path prepended). */
  backendPath: string
}

export interface HostServiceDetail extends HostService {
  routes: HostRoute[]
  catchAll: { access: Access; backendPath: string } | null
}

export interface HostDetail extends Omit<HostEntry, 'services'> {
  services: HostServiceDetail[]
}

/**
 * The path the backend receives for a request path, as the gateway forwards it: Oathkeeper removes the
 * first occurrence of `strip_path`, then joins the upstream URL's path (`upstream.path`) in front.
 */
export function backendPathOf(path: string, upstream: Pick<Site['upstream'], 'stripPath' | 'path'> | null): string {
  if (!upstream) return path
  let rest = upstream.stripPath && path.includes(upstream.stripPath) ? path.replace(upstream.stripPath, '') : path
  if (!rest.startsWith('/')) rest = `/${rest}`
  const base = (upstream.path ?? '').replace(/\/+$/, '')
  return `${base}${rest}` || '/'
}

const tokenAuthenticators = new Set(['oauth2_introspection', 'jwt'])

function usedGates(site: Site): Gate[] {
  const ids = new Set<string>()
  for (const r of site.routes.items) if (r.access.kind !== 'deny') ids.add(r.gate)
  if (site.routes.catchAll.access.kind !== 'deny') ids.add(site.routes.catchAll.gate)
  return site.gates.filter((g) => ids.has(g.id))
}

export function kindOf(site: Site): 'page' | 'api' {
  const gates = usedGates(site)
  return gates.length > 0 && gates.every((g) => g.errors === 'api') ? 'api' : 'page'
}

export function accessSummaryOf(site: Site): AccessSummary {
  const accesses = [...site.routes.items.map((r) => r.access), site.routes.catchAll.access]
  const permissions = [...new Set(accesses.flatMap((a) => (a.kind === 'permission' ? [a.permission] : [])))].sort()
  const tokens = usedGates(site).some((g) => g.authenticators.some((h) => tokenAuthenticators.has(h.handler)))
  return {
    public: accesses.some((a) => a.kind === 'public'),
    signedIn: accesses.some((a) => a.kind === 'signed-in'),
    permissions,
    orgKeys: organizationsOn(site) && tokens,
  }
}

interface Mounted { site: Site; status: SiteStatus; draft: boolean }

/** The sites as they will be grouped: every saved one, plus each never-saved draft that names a host and an upstream. */
async function mounted(): Promise<Mounted[]> {
  const [records, drafts] = await Promise.all([sitesRepository.list(), sitesRepository.drafts()])
  const known = new Set(records.map((r) => r.site.name))
  const draftOf = new Map(drafts.map((d) => [d.name, d.draft]))
  const saved = records.map((r: SiteRecord) => {
    const kept = draftOf.get(r.site.name)
    return { site: r.site, status: statusOf(r), draft: !!kept && !draftChangesNothing(kept, r) }
  })
  const draftOnly = drafts.flatMap(({ name, draft }): Mounted[] => {
    if (known.has(name)) return []
    const s = (draft.site ?? {}) as Partial<Site>
    if (typeof s.address?.host !== 'string' || !s.upstream || !s.routes || !Array.isArray(s.gates)) return []
    return [{ site: { ...s, name, displayName: s.displayName || name } as Site, status: 'draft', draft: true }]
  })
  return [...saved, ...draftOnly]
}

const upstreamKey = (s: Site) => `${s.upstream.namespace}/${s.upstream.service}`
const byPath = (a: HostService, b: HostService) => (a.pathPrefix ?? '').localeCompare(b.pathPrefix ?? '') || a.site.localeCompare(b.site)

function serviceOf(m: Mounted, onHost: readonly Mounted[], shared: Map<string, string[]>, pending: Set<string>): HostService {
  const { site } = m
  const prefix = site.address.pathPrefix
  const enclosing = onHost
    .filter((o) => o.site.name !== site.name && prefixContains(o.site.address.pathPrefix, prefix))
    .sort((a, b) => (b.site.address.pathPrefix ?? '').length - (a.site.address.pathPrefix ?? '').length)
  const u = site.upstream
  return {
    site: site.name,
    displayName: site.displayName,
    pathPrefix: prefix ?? null,
    parent: enclosing[0]?.site.name ?? null,
    upstream: u ? { service: u.service, namespace: u.namespace, port: u.port, ...(u.stripPath ? { stripPath: u.stripPath } : {}), ...(u.path ? { path: u.path } : {}) } : null,
    kind: kindOf(site),
    access: accessSummaryOf(site),
    status: m.status,
    draft: m.draft,
    pendingRequest: pending.has(site.name),
    sharedBackendWith: (shared.get(upstreamKey(site)) ?? []).filter((n) => n !== site.name),
  }
}

async function zoneOf(): Promise<(host: string) => string | null> {
  try {
    const zones = await loadZones()
    const cookie = sitesConfig().SITES_COOKIE_DOMAIN
    return (host) => placeHost(host, zones, cookie).zone
  } catch {
    return () => null
  }
}

async function grouped(): Promise<Array<{ host: string; zone: string | null; services: Array<{ m: Mounted; s: HostService }> }>> {
  const [all, zone, requests] = await Promise.all([mounted(), zoneOf(), listRequests({ state: 'pending' }).catch(() => [])])
  const pending = new Set(requests.map((r) => r.site))
  const shared = new Map<string, string[]>()
  for (const m of all) shared.set(upstreamKey(m.site), [...(shared.get(upstreamKey(m.site)) ?? []), m.site.name].sort())
  const hosts = new Map<string, Mounted[]>()
  for (const m of all) {
    const h = m.site.address.host.toLowerCase()
    hosts.set(h, [...(hosts.get(h) ?? []), m])
  }
  return [...hosts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([host, onHost]) => ({
    host,
    zone: zone(host),
    services: onHost.map((m) => ({ m, s: serviceOf(m, onHost, shared, pending) })).sort((a, b) => byPath(a.s, b.s)),
  }))
}

const countsOf = (services: readonly HostService[]) => ({
  services: services.length,
  live: services.filter((s) => s.status === 'live').length,
  drafts: services.filter((s) => s.draft || s.status === 'draft').length,
  pendingRequests: services.filter((s) => s.pendingRequest).length,
})

/** Every host, with its services (GET /api/admin/sites/hosts). */
export async function listHosts(): Promise<HostEntry[]> {
  return (await grouped()).map(({ host, zone, services }) => {
    const list = services.map((x) => x.s)
    return { host, zone, services: list, counts: countsOf(list) }
  })
}

/** One host in detail: each service's routes with the path its backend receives (GET /api/admin/sites/hosts/:host). */
export async function getHost(host: string): Promise<HostDetail> {
  const entry = (await grouped()).find((h) => h.host === host.toLowerCase())
  if (!entry) throw siteError(404, 'not_found', `No site is on ${host}`)
  const services = entry.services.map(({ m, s }): HostServiceDetail => {
    const u = m.site.upstream ?? null
    const prefix = m.site.address.pathPrefix ?? ''
    return {
      ...s,
      routes: m.site.routes.items.map((r) => ({ id: r.id, methods: [...r.methods], path: r.path, access: r.access, backendPath: backendPathOf(r.path, u) })),
      catchAll: { access: m.site.routes.catchAll.access, backendPath: backendPathOf(`${prefix}/…`, u) },
    }
  })
  return { host: entry.host, zone: entry.zone, services, counts: countsOf(services) }
}
