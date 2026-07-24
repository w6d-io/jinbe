import { redisRbacRepository, type GroupDefinition, type FlatRolesMap, type RouteMap, type OathkeeperRule } from './redis-rbac.repository.js'
import { auditEventService } from './audit-event.service.js'
import { rbacService } from './rbac.service.js'
import { defaultServiceRoles } from './rbac-defaults.js'

export interface AuthBundle {
  version: '1'
  exportedAt: string
  rbac: {
    services: string[]
    groups: Record<string, GroupDefinition>
    roles: Record<string, FlatRolesMap>
    routeMaps: Record<string, RouteMap>
    oathkeeperRules: OathkeeperRule[]
    // Org → service bundle. Exported as arrays; legacy bundles that stored a
    // scalar per org are tolerated on import (see import() below).
    orgServiceMap?: Record<string, string[]>
  }
}

export type BundleSection = 'services' | 'groups' | 'roles' | 'routeMaps' | 'oathkeeperRules' | 'orgServiceMap'
export const ALL_BUNDLE_SECTIONS: BundleSection[] = ['services', 'groups', 'roles', 'routeMaps', 'oathkeeperRules', 'orgServiceMap']

export interface ImportResult {
  rbac: {
    services: number
    groups: number
    roles: number
    routeMaps: number
    oathkeeperRules: number
  }
}

class RbacBundleService {
  // `sections` (optional) narrows a MANUAL export/download to selected parts.
  // Omitted → full 1:1 snapshot (what the backup CronJob + restore use).
  async export(sections?: BundleSection[]): Promise<AuthBundle> {
    const [services, groups, oathkeeperRules, orgServiceMap] = await Promise.all([
      redisRbacRepository.getServices(),
      redisRbacRepository.getGroups(),
      redisRbacRepository.getAccessRules(),
      redisRbacRepository.getOrgServiceMap(),
    ])

    const allServiceKeys = [...services, 'global']
    const [rolesEntries, routeMapEntries] = await Promise.all([
      Promise.all(allServiceKeys.map(async svc => [svc, await redisRbacRepository.getRoles(svc)] as const)),
      Promise.all(services.map(async svc => [svc, await redisRbacRepository.getRouteMap(svc)] as const)),
    ])

    const roles: Record<string, FlatRolesMap> = {}
    for (const [svc, r] of rolesEntries) {
      if (r) roles[svc] = r
    }
    const routeMaps: Record<string, RouteMap> = {}
    for (const [svc, rm] of routeMapEntries) {
      if (rm) routeMaps[svc] = rm
    }

    const fullRbac = { services, groups, roles, routeMaps, oathkeeperRules, orgServiceMap }
    let rbac: AuthBundle['rbac'] = fullRbac
    if (sections && sections.length && sections.length < ALL_BUNDLE_SECTIONS.length) {
      const picked: Partial<typeof fullRbac> = {}
      for (const s of sections) if (s in fullRbac) (picked as Record<string, unknown>)[s] = fullRbac[s]
      rbac = picked as AuthBundle['rbac']
    }
    return { version: '1', exportedAt: new Date().toISOString(), rbac }
  }

  async import(bundle: AuthBundle, actor?: { email?: string; ip?: string }): Promise<ImportResult> {
    const { services, groups, roles, routeMaps, oathkeeperRules, orgServiceMap } = bundle.rbac

    // ── Service registry: full replace ──
    const existingServices = await redisRbacRepository.getServices()
    await Promise.all(existingServices.map(svc => redisRbacRepository.removeService(svc)))
    await Promise.all(services.map(svc => redisRbacRepository.addService(svc)))

    // ── Prune for a true 1:1 restore: drop roles/routeMaps of services that are
    // no longer in the bundle (the old upsert-only import left these orphaned). ──
    const bundleServices = new Set(services)
    const orphanServices = existingServices.filter(svc => !bundleServices.has(svc))
    await Promise.all(orphanServices.flatMap(svc => [
      redisRbacRepository.deleteRoles(svc),
      redisRbacRepository.deleteRouteMap(svc),
    ]))

    // ── Groups: overwrite the bundle's, prune any group absent from the bundle ──
    const existingGroups = await redisRbacRepository.getGroups()
    for (const name of Object.keys(existingGroups)) {
      if (!(name in groups)) await redisRbacRepository.deleteGroup(name)
    }
    for (const [name, def] of Object.entries(groups)) {
      await redisRbacRepository.setGroup(name, def)
    }

    // ── Roles: AUTOFIX — every imported service ends up with the full default
    // roles. Defaults fill gaps; the bundle's own definitions win on conflict.
    // 'global' is not a service, so it passes through untouched. ──
    for (const [svc, r] of Object.entries(roles)) {
      const merged = svc === 'global' ? r : { ...defaultServiceRoles(svc), ...r }
      await redisRbacRepository.setRoles(svc, merged)
    }
    // A service listed in the registry but with no roles entry still gets defaults.
    for (const svc of services) {
      if (!(svc in roles)) await redisRbacRepository.setRoles(svc, defaultServiceRoles(svc))
    }

    for (const [svc, rm] of Object.entries(routeMaps)) {
      await redisRbacRepository.setRouteMap(svc, rm)
    }

    await redisRbacRepository.setAccessRules(oathkeeperRules)

    if (orgServiceMap && Object.keys(orgServiceMap).length > 0) {
      for (const [orgId, svcs] of Object.entries(orgServiceMap)) {
        // Tolerate a legacy bundle whose values are a scalar service name
        // (pre-migration export) as well as the current array shape.
        const mapped = Array.isArray(svcs) ? svcs : [svcs as unknown as string]
        await redisRbacRepository.setOrgServiceMapping(orgId, mapped)
      }
    }

    auditEventService.emit({
      category: 'rbac',
      verb:     'import',
      target:   'bundle',
      result:   'ok',
      actor:    { email: actor?.email ?? null, ip: actor?.ip ?? null },
      reason:   `services=${services.length}`,
    }).catch(() => {})

    // Propagate to OPAL/OPA immediately (the fix): etag bump + real-time push +
    // OPAL data refresh — otherwise OPA serves the pre-restore dataset until the
    // next unrelated mutation or a jinbe restart.
    await rbacService.invalidateBundle('rbac.bundle_imported', { type: 'bundle' }, actor)

    return {
      rbac: {
        services: services.length,
        groups: Object.keys(groups).length,
        roles: Object.keys(roles).length,
        routeMaps: Object.keys(routeMaps).length,
        oathkeeperRules: oathkeeperRules.length,
      },
    }
  }
}

export const rbacBundleService = new RbacBundleService()
