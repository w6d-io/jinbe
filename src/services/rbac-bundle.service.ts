import { kratosService } from './kratos.service.js'
import { redisRbacRepository, type GroupDefinition, type FlatRolesMap, type RouteMap, type OathkeeperRule } from './redis-rbac.repository.js'
import { auditEventService } from './audit-event.service.js'

export interface IdentityExport {
  email: string
  name: string | null
  groups: string[]
  state: string
}

export interface AuthBundle {
  version: '1'
  exportedAt: string
  rbac: {
    services: string[]
    groups: Record<string, GroupDefinition>
    roles: Record<string, FlatRolesMap>
    routeMaps: Record<string, RouteMap>
    oathkeeperRules: OathkeeperRule[]
  }
  identities: IdentityExport[]
}

export interface ImportResult {
  rbac: {
    services: number
    groups: number
    roles: number
    routeMaps: number
    oathkeeperRules: number
  }
  identities: {
    created: number
    updated: number
    skipped: number
  }
}

class RbacBundleService {
  /**
   * Export all RBAC config + Kratos identities as a portable bundle.
   */
  async export(): Promise<AuthBundle> {
    const [services, groups, oathkeeperRules] = await Promise.all([
      redisRbacRepository.getServices(),
      redisRbacRepository.getGroups(),
      redisRbacRepository.getAccessRules(),
    ])

    // Fetch roles + routeMaps for all services (+ global roles)
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

    // Fetch Kratos identities
    const { identities: kratosIdentities } = await kratosService.listIdentities(1000)
    const identities: IdentityExport[] = kratosIdentities.map(id => ({
      email: id.traits.email,
      name: (id.traits as { name?: string }).name ?? null,
      groups: ((id.metadata_admin as { groups?: string[] } | null)?.groups) ?? [],
      state: id.state ?? 'active',
    }))

    return {
      version: '1',
      exportedAt: new Date().toISOString(),
      rbac: { services, groups, roles, routeMaps, oathkeeperRules },
      identities,
    }
  }

  /**
   * Import a bundle — upserts RBAC config and Kratos identities.
   *
   * RBAC data: full replace (existing data cleared).
   * Identities: upsert by email — updates groups for existing users,
   *             creates new identities with a temp password for new ones.
   */
  async import(bundle: AuthBundle, actor?: { email?: string; ip?: string }): Promise<ImportResult> {
    const { services, groups, roles, routeMaps, oathkeeperRules } = bundle.rbac

    // ── RBAC ────────────────────────────────────────────────────────────────────
    // Replace services set
    const existingServices = await redisRbacRepository.getServices()
    await Promise.all(existingServices.map(svc => redisRbacRepository.removeService(svc)))
    await Promise.all(services.map(svc => redisRbacRepository.addService(svc)))

    // Replace groups
    for (const [name, def] of Object.entries(groups)) {
      await redisRbacRepository.setGroup(name, def)
    }

    // Replace roles (per service)
    for (const [svc, r] of Object.entries(roles)) {
      await redisRbacRepository.setRoles(svc, r)
    }

    // Replace routeMaps (per service)
    for (const [svc, rm] of Object.entries(routeMaps)) {
      await redisRbacRepository.setRouteMap(svc, rm)
    }

    // Replace oathkeeper rules
    await redisRbacRepository.setAccessRules(oathkeeperRules)

    // ── Identities ──────────────────────────────────────────────────────────────
    let created = 0, updated = 0, skipped = 0

    for (const id of bundle.identities) {
      try {
        const response = await kratosService.listIdentities(1, undefined, id.email)
        if (response.identities.length > 0) {
          // Exists: update groups only
          await kratosService.updateUserGroups(id.email, id.groups)
          updated++
        } else {
          // New: create with temp password — user must set their own via recovery
          await kratosService.createIdentity({
            schema_id: 'default',
            state: (id.state === 'active' || id.state === 'inactive') ? id.state : 'active',
            traits: { email: id.email, name: id.name ?? '' },
            metadata_admin: { groups: id.groups },
            credentials: {
              password: { config: { password: generateTempPassword() } },
            },
          })
          created++
        }
      } catch (err) {
        console.error(`[bundle-import] Failed to import identity ${id.email}:`, err)
        skipped++
      }
    }

    kratosService.invalidateGroupsCache()

    auditEventService.emit({
      category: 'rbac',
      verb:     'import',
      target:   'bundle',
      result:   'ok',
      actor:    { email: actor?.email ?? null, ip: actor?.ip ?? null },
      reason:   `services=${services.length} identities=${bundle.identities.length} (created=${created} updated=${updated} skipped=${skipped})`,
    }).catch(() => {})

    return {
      rbac: {
        services: services.length,
        groups: Object.keys(groups).length,
        roles: Object.keys(roles).length,
        routeMaps: Object.keys(routeMaps).length,
        oathkeeperRules: oathkeeperRules.length,
      },
      identities: { created, updated, skipped },
    }
  }
}

function generateTempPassword(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$'
  let pwd = ''
  for (let i = 0; i < 20; i++) pwd += chars[Math.floor(Math.random() * chars.length)]
  return pwd
}

export const rbacBundleService = new RbacBundleService()
