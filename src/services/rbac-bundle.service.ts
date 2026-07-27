import { redisRbacRepository, type GroupDefinition, type FlatRolesMap, type RouteMap, type OathkeeperRule } from './redis-rbac.repository.js'
import { auditEventService, type AuditActorInput, type AuditFlag } from './audit-event.service.js'
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

  async import(bundle: AuthBundle, actor?: AuditActorInput, sections?: BundleSection[]): Promise<ImportResult> {
    const { services, groups, roles, routeMaps, oathkeeperRules, orgServiceMap } = bundle.rbac
    // `sections` (optional) restricts a selective import to the chosen parts.
    // Full 1:1 restore (prune orphans) happens ONLY when applying the whole
    // bundle; a selective import overrides/adds the chosen sections and NEVER
    // prunes anything outside them.
    const want = (s: BundleSection) => !sections || sections.length === 0 || sections.includes(s)
    const isFull = !sections || sections.length === 0 || sections.length >= ALL_BUNDLE_SECTIONS.length

    const existingServices = await redisRbacRepository.getServices()
    let orphanServices: string[] = []

    // ── Service registry ──
    if (want('services')) {
      await Promise.all(services.map(svc => redisRbacRepository.addService(svc)))
      if (isFull) {
        // True 1:1 restore: drop services (and their roles/routeMaps) not in the bundle.
        const bundleServices = new Set(services)
        orphanServices = existingServices.filter(svc => !bundleServices.has(svc))
        await Promise.all(orphanServices.map(svc => redisRbacRepository.removeService(svc)))
        await Promise.all(orphanServices.flatMap(svc => [
          redisRbacRepository.deleteRoles(svc),
          redisRbacRepository.deleteRouteMap(svc),
        ]))
      }
    }

    // ── Groups: overwrite the bundle's; prune absent ones only on a full restore ──
    if (want('groups')) {
      if (isFull) {
        const existingGroups = await redisRbacRepository.getGroups()
        for (const name of Object.keys(existingGroups)) {
          if (!(name in groups)) await redisRbacRepository.deleteGroup(name)
        }
      }
      for (const [name, def] of Object.entries(groups)) {
        await redisRbacRepository.setGroup(name, def)
      }
    }

    // ── Roles: AUTOFIX — defaults fill gaps; the bundle's definitions win.
    // 'global' is not a service, so it passes through untouched. ──
    if (want('roles')) {
      for (const [svc, r] of Object.entries(roles)) {
        const merged = svc === 'global' ? r : { ...defaultServiceRoles(svc), ...r }
        await redisRbacRepository.setRoles(svc, merged)
      }
      // A newly-added service with no roles entry still gets defaults (only when
      // the services section was also applied, so we don't seed untouched services).
      if (want('services')) {
        for (const svc of services) {
          if (!(svc in roles)) await redisRbacRepository.setRoles(svc, defaultServiceRoles(svc))
        }
      }
    }

    if (want('routeMaps')) {
      for (const [svc, rm] of Object.entries(routeMaps)) {
        await redisRbacRepository.setRouteMap(svc, rm)
      }
    }

    if (want('oathkeeperRules')) {
      await redisRbacRepository.setAccessRules(oathkeeperRules)
    }

    if (want('orgServiceMap') && orgServiceMap && Object.keys(orgServiceMap).length > 0) {
      for (const [orgId, svcs] of Object.entries(orgServiceMap)) {
        // Tolerate a legacy bundle whose values are a scalar service name
        // (pre-migration export) as well as the current array shape.
        const mapped = Array.isArray(svcs) ? svcs : [svcs as unknown as string]
        await redisRbacRepository.setOrgServiceMapping(orgId, mapped)
      }
    }

    // A full restore is high-signal — flag it if any imported group grants the
    // global super_admin role (structural, no secrets in the envelope).
    const flags: AuditFlag[] = []
    const grantsSuper = Object.values(groups).some((def) => (def.global ?? []).includes('super_admin'))
    if (grantsSuper) flags.push('grants_super_admin')

    auditEventService.emit({
      category: 'rbac',
      kind:     'change',
      verb:     'import',
      target:   'bundle',
      result:   'applied',
      severity: grantsSuper ? 'high' : 'warn',
      actor:    { email: actor?.email ?? null, ip: actor?.ip ?? null, name: actor?.name, ua: actor?.ua, sessionId: actor?.sessionId },
      requestId: actor?.requestId,
      reason:   `services=${services.length}`,
      changes: {
        resource: 'bundle',
        added:    want('services') ? services : [],
        removed:  orphanServices,
        flags:    flags.length ? flags : undefined,
        summary:  isFull
          ? `full restore — ${services.length} services, ${Object.keys(groups).length} groups, ${oathkeeperRules.length} rules`
          : `imported sections: ${(sections ?? []).join(', ')}`,
      },
    }).catch(() => {})

    // Propagate to OPAL/OPA immediately (the fix): etag bump + real-time push +
    // OPAL data refresh — otherwise OPA serves the pre-restore dataset until the
    // next unrelated mutation or a jinbe restart. [P2-4] Pass eventType=undefined
    // so invalidateBundle does NOT emit a second (diff-less) event — the rich
    // event above is the single audit record for the import.
    await rbacService.invalidateBundle(undefined, { type: 'bundle' }, actor)

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
