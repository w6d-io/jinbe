import { redisRbacRepository, type FlatRolesMap, type RouteMap } from './redis-rbac.repository.js'
import { env } from '../config/env.js'

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
    // Roles of every service plus "global" (data.roles.<svc>). Global is not in the services registry
    // but always present: it holds the platform-wide wildcard ("*") of the super_admin role, and the
    // rego super_admin detector relies on data.roles.global being populated.
    { url: `${jinbeUrl}/api/admin/rbac/opal/roles`, topics: ['policy_data'], dst_path: '/roles' },
    // Route map of every service that has one (data.route_map.<svc>).
    { url: `${jinbeUrl}/api/admin/rbac/opal/route_maps`, topics: ['policy_data'], dst_path: '/route_map' },
    // Org → service map (data.org_service_map): the delegation rego resolves
    // which service a target org's RBAC lives under from this.
    { url: `${jinbeUrl}/api/admin/rbac/opal/org_service_map`, topics: ['policy_data'], dst_path: '/org_service_map' },
    // Org → admin roster (data.org_admin_map): per-org list of admin emails;
    // manageable_orgs + the org-mgmt allow clause resolve org admins from it.
    { url: `${jinbeUrl}/api/admin/rbac/opal/org_admin_map`, topics: ['policy_data'], dst_path: '/org_admin_map' },
    // Org grants (data.org_grants): groups an org admin handed out in THEIR org; the org layer
    // counts them only on that org's routes.
    { url: `${jinbeUrl}/api/admin/rbac/opal/org_grants`, topics: ['policy_data'], dst_path: '/org_grants' },
    // Per-site 2FA (data.site_login): the bar each Site sets, published with its permissions.
    { url: `${jinbeUrl}/api/admin/rbac/opal/site_login`, topics: ['policy_data'], dst_path: '/site_login' },
    // Platform 2FA (data.second_factor): groups whose members need aal2 on every permission route.
    { url: `${jinbeUrl}/api/admin/rbac/opal/second_factor`, topics: ['policy_data'], dst_path: '/second_factor' },
    // Org API keys (data.api_clients): a machine caller's organization and registered scopes, so a site
    // route is granted to a client only in its own org and only as far as its scopes reach.
    { url: `${jinbeUrl}/api/admin/rbac/opal/api_clients`, topics: ['policy_data'], dst_path: '/api_clients' },
  ]
  if (env.RBAC_V2_PUBLISH) {
    // authz v2, side by side: the whole v2 model in one document, and the switch the router reads.
    entries.push(
      { url: `${jinbeUrl}/api/admin/rbac/opal/v2`, topics: ['policy_data'], dst_path: '/v2' },
      { url: `${jinbeUrl}/api/admin/rbac/opal/authz`, topics: ['policy_data'], dst_path: '/authz' },
    )
  }

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
 * data.roles: { <svc>: roles } for "global" and every registered service — `{}` for one with no roles,
 * exactly what the former per-service entries wrote. A read error throws: the route answers 5xx and
 * OPAL keeps what OPA holds, never a partial map (the entry replaces the whole subtree).
 */
export async function opalRolesDataset(): Promise<Record<string, FlatRolesMap>> {
  const services = [...new Set(['global', ...(await redisRbacRepository.getServices())])]
  const roles = await Promise.all(services.map(async (svc) => [svc, (await redisRbacRepository.getRoles(svc)) || {}] as const))
  return Object.fromEntries(roles)
}

/** data.route_map: { <svc>: route map } for every registered service that has one. Throws like roles. */
export async function opalRouteMapsDataset(): Promise<Record<string, RouteMap>> {
  const services = await redisRbacRepository.getServices()
  const maps = await Promise.all(services.map(async (svc) => [svc, await redisRbacRepository.getRouteMap(svc)] as const))
  return Object.fromEntries(maps.filter((m): m is readonly [string, RouteMap] => !!m[1]))
}
