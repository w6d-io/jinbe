import { redisRbacRepository } from './redis-rbac.repository.js'
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
 */
export async function buildOpalDatasourceEntries(): Promise<OpalDataSourceEntry[]> {
  const services = await redisRbacRepository.getServices()
  const jinbeUrl = env.JINBE_INTERNAL_URL || 'http://jinbe:8080'

  const entries = [
    { url: `${jinbeUrl}/api/admin/rbac/bindings`, topics: ['policy_data'], dst_path: '/bindings' },
    { url: `${jinbeUrl}/api/admin/rbac/opal/groups`, topics: ['policy_data'], dst_path: '/bindings/groups' },
    // Global roles are always part of OPA's dataset, even though "global"
    // is not listed in the services registry — they hold the platform-wide
    // wildcard ("*") used by the super_admin role and the rego super_admin
    // detector relies on data.roles.global being populated.
    { url: `${jinbeUrl}/api/admin/rbac/opal/roles/global`, topics: ['policy_data'], dst_path: '/roles/global' },
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
  ]

  for (const svc of services) {
    entries.push({ url: `${jinbeUrl}/api/admin/rbac/opal/roles/${svc}`, topics: ['policy_data'], dst_path: `/roles/${svc}` })
    const routeMap = await redisRbacRepository.getRouteMap(svc)
    if (routeMap) {
      entries.push({ url: `${jinbeUrl}/api/admin/rbac/opal/route_map/${svc}`, topics: ['policy_data'], dst_path: `/route_map/${svc}` })
    }
  }

  // The client sends this on every data fetch.
  const config = { headers: { Authorization: `Bearer ${env.OPAL_CLIENT_TOKEN}` } }
  const refresh = env.OPAL_DATA_REFRESH_SECONDS > 0 ? { periodic_update_interval: env.OPAL_DATA_REFRESH_SECONDS } : {}
  return entries.map((entry) => ({ ...entry, config, ...refresh }))
}
