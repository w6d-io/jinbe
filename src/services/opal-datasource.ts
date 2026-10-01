import { redisRbacRepository, type FlatRolesMap, type RouteMap } from './redis-rbac.repository.js'
import { env } from '../config/env.js'
import { JINBE } from '../policy/roles.js'
import { kratosService } from './kratos.service.js'
import { allOrganisations, organisationStoreConfigured } from './organisation-store.js'

/**
 * One OPAL data source entry (opal_common/schemas/data.py `DataSourceEntryWithPollingInterval`).
 * `periodic_update_interval` is read by the OPAL client from the manifest it pulls on connect
 * (opal_client/data/updater.py `get_base_policy_data`): such an entry is fetched at once and then
 * every that-many seconds, so OPA heals on its own when a push is lost.
 */
export interface OpalDataSourceEntry {
  url: string
  topics: string[]
  dst_path: string
  config: { headers: { Authorization: string } }
  periodic_update_interval?: number
}

/**
 * Everything OPA needs from jinbe. Serves GET /opal-datasource AND the push to opal-server after a
 * change, so the two can never list different entries.
 *
 * The list is FIXED: it never depends on which services exist. Roles and route maps go out as one
 * entry each, covering every service. The OPAL client builds its periodic-refresh set from the
 * manifest it pulls on connect, so a per-service entry for a service registered after that connect
 * was refreshed only on push — a lost push left it stale until the client reconnected.
 */
export async function buildOpalDatasourceEntries(): Promise<OpalDataSourceEntry[]> {
  const jinbeUrl = env.JINBE_INTERNAL_URL || 'http://jinbe:8080'

  const entries = [
    // All of data.bindings, `groups` included. No entry may sit under another's dst_path: OPAL PUTs each
    // entry on its own and OPA's PUT replaces the subtree, so a parent's write wipes its child until the
    // child's own write lands — /bindings/groups as its own entry denied every group role for that window.
    { url: `${jinbeUrl}/api/admin/rbac/bindings`, topics: ['policy_data'], dst_path: '/bindings' },
    // Roles of every service (data.roles.<svc>), jinbe's staff roles among them. No `global` scope.
    { url: `${jinbeUrl}/api/admin/rbac/opal/roles`, topics: ['policy_data'], dst_path: '/roles' },
    // Route map of every service that has one (data.route_map.<svc>).
    { url: `${jinbeUrl}/api/admin/rbac/opal/route_maps`, topics: ['policy_data'], dst_path: '/route_map' },
    // Org roles of every service (data.org_roles.<svc>): what an org role assigned in an org gives there.
    { url: `${jinbeUrl}/api/admin/rbac/opal/org_roles`, topics: ['policy_data'], dst_path: '/org_roles' },
    // What a platform role carries into every org (data.every_org.<app>) — the only such path.
    { url: `${jinbeUrl}/api/admin/rbac/opal/every_org`, topics: ['policy_data'], dst_path: '/every_org' },
    // Org → entitled apps (data.org_sites), jinbe for every org: an org role of a site counts only there.
    { url: `${jinbeUrl}/api/admin/rbac/opal/org_sites`, topics: ['policy_data'], dst_path: '/org_sites' },
    // Per-site 2FA (data.site_login): the bar each Site sets, published with its permissions.
    { url: `${jinbeUrl}/api/admin/rbac/opal/site_login`, topics: ['policy_data'], dst_path: '/site_login' },
    // Platform 2FA (data.second_factor): groups whose members need aal2 on every permission route.
    { url: `${jinbeUrl}/api/admin/rbac/opal/second_factor`, topics: ['policy_data'], dst_path: '/second_factor' },
    // Org API keys (data.api_clients): a machine caller's organization and registered scopes, so a site
    // route is granted to a client only in its own org and only as far as its scopes reach.
    { url: `${jinbeUrl}/api/admin/rbac/opal/api_clients`, topics: ['policy_data'], dst_path: '/api_clients' },
  ]
  // The client sends this on every data fetch.
  const config = { headers: { Authorization: `Bearer ${env.OPAL_CLIENT_TOKEN}` } }
  const refresh = env.OPAL_DATA_REFRESH_SECONDS > 0 ? { periodic_update_interval: env.OPAL_DATA_REFRESH_SECONDS } : {}
  return entries.map((entry) => ({ ...entry, config, ...refresh }))
}

/**
 * An entry's name as the fetch metrics and the Home file it (`bindings`, `opal/roles`): its path
 * under /admin/rbac/.
 */
export function opalEntryName(url: string): string {
  return new URL(url).pathname.replace(/^.*\/admin\/rbac\/(develop\/)?/, '')
}

/**
 * data.roles: { <svc>: roles } for every registered service — `{}` for one with no roles. A read error
 * throws: the route answers 5xx and OPAL keeps what OPA holds, never a partial map (the entry replaces
 * the whole subtree).
 */
export async function opalRolesDataset(): Promise<Record<string, FlatRolesMap>> {
  return perService((svc) => redisRbacRepository.getRoles(svc))
}

async function perService(read: (svc: string) => Promise<FlatRolesMap | null>): Promise<Record<string, FlatRolesMap>> {
  const services = [...new Set([JINBE, ...(await redisRbacRepository.getServices())])]
  const values = await Promise.all(services.map(async (svc) => [svc, (await read(svc)) || {}] as const))
  return Object.fromEntries(values)
}

/** data.org_roles: { <svc>: org roles }. Throws like roles. */
export async function opalOrgRolesDataset(): Promise<Record<string, FlatRolesMap>> {
  return perService((svc) => redisRbacRepository.getOrgRoles(svc))
}

/** data.every_org: { <app>: { platform role: [org permission] } }. Throws like roles. */
export async function opalEveryOrgDataset(): Promise<Record<string, FlatRolesMap>> {
  return perService((svc) => redisRbacRepository.getEveryOrg(svc))
}

/**
 * data.org_sites: every known organisation → [jinbe, …the sites entitling it]. Known = the registry
 * (when this service owns organisations), every org an identity belongs to, and every org a site
 * names. Its keys are the org universe the policy lists every-org reach over. Throws when a source
 * cannot be read: a missing org would quietly take every-org reach (and its own roles) away there.
 */
export async function opalOrgSitesDataset(): Promise<Record<string, string[]>> {
  const [entitled, bindings, registry] = await Promise.all([
    redisRbacRepository.getOrgSites(),
    kratosService.getAllIdentitiesWithBindings(),
    organisationStoreConfigured() ? allOrganisations().then((orgs) => orgs.map((o) => o.id)) : Promise.resolve([] as string[]),
  ])
  const orgs = new Set<string>([...Object.keys(entitled), ...registry])
  for (const b of bindings.values()) {
    if (b.primaryOrganization) orgs.add(b.primaryOrganization)
    for (const o of b.organizations) if (o) orgs.add(o)
  }
  return Object.fromEntries([...orgs].sort().map((o) => [o, [...new Set([JINBE, ...(entitled[o] ?? [])])]]))
}

/** data.route_map: { <svc>: route map } for every registered service that has one. Throws like roles. */
export async function opalRouteMapsDataset(): Promise<Record<string, RouteMap>> {
  const services = await redisRbacRepository.getServices()
  const maps = await Promise.all(services.map(async (svc) => [svc, await redisRbacRepository.getRouteMap(svc)] as const))
  return Object.fromEntries(maps.filter((m): m is readonly [string, RouteMap] => !!m[1]))
}
