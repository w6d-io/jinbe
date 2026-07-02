import { redisRbacRepository, type GroupDefinition, type FlatRolesMap, type RouteMap, type OathkeeperRule } from './redis-rbac.repository.js'
import { auditEventService } from './audit-event.service.js'

export interface AuthBundle {
  version: '1'
  exportedAt: string
  rbac: {
    services: string[]
    groups: Record<string, GroupDefinition>
    roles: Record<string, FlatRolesMap>
    routeMaps: Record<string, RouteMap>
    oathkeeperRules: OathkeeperRule[]
    orgServiceMap?: Record<string, string>
  }
}

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
  async export(): Promise<AuthBundle> {
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

    return {
      version: '1',
      exportedAt: new Date().toISOString(),
      rbac: { services, groups, roles, routeMaps, oathkeeperRules, orgServiceMap },
    }
  }

  async import(bundle: AuthBundle, actor?: { email?: string; ip?: string }): Promise<ImportResult> {
    const { services, groups, roles, routeMaps, oathkeeperRules, orgServiceMap } = bundle.rbac

    const existingServices = await redisRbacRepository.getServices()
    await Promise.all(existingServices.map(svc => redisRbacRepository.removeService(svc)))
    await Promise.all(services.map(svc => redisRbacRepository.addService(svc)))

    for (const [name, def] of Object.entries(groups)) {
      await redisRbacRepository.setGroup(name, def)
    }

    for (const [svc, r] of Object.entries(roles)) {
      await redisRbacRepository.setRoles(svc, r)
    }

    for (const [svc, rm] of Object.entries(routeMaps)) {
      await redisRbacRepository.setRouteMap(svc, rm)
    }

    await redisRbacRepository.setAccessRules(oathkeeperRules)

    if (orgServiceMap && Object.keys(orgServiceMap).length > 0) {
      for (const [orgId, svcName] of Object.entries(orgServiceMap)) {
        await redisRbacRepository.setOrgServiceMapping(orgId, svcName)
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
