import { redisRbacRepository, type GroupDefinition } from '../services/redis-rbac.repository.js'
import { withRedisLock } from '../services/redis-lock.js'
import { rbacService } from '../services/rbac.service.js'
import type { AuditActorInput } from '../services/audit-event.service.js'
import { findRouteTies, loadPublishedRouteRules, routeTieConflict, type PinnedHosts } from '../policy/route-ties.js'
import { assertOrgParams } from '../policy/route-org-param.js'
import type { Rendered } from './render.js'

/**
 * A site's permissions in the keys OPA is fed from (route_map, roles, services, groups,
 * org_service_map) — written BEFORE its gateway rules, so a new route fails closed until its
 * permission exists — and taken out again after its rules are gone.
 *
 * Reconciling, not diffing: every group and org entry naming the site is brought to exactly what
 * this render says, so a publish also repairs whatever an earlier half-finished one left behind.
 * Only keys the site owns are touched: its own service entries, its `<site>-…` org-grantable
 * groups, and the site's column in shared groups.
 */

export type Permissions = Pick<Rendered, 'routeMap' | 'roles' | 'groups' | 'orgServiceMap'>

const EMPTY: Permissions = { routeMap: [], roles: {}, groups: { platform: {}, orgGrantable: {} }, orgServiceMap: {} }

export async function publishPermissions(
  name: string,
  perms: Permissions,
  ctx: { description?: string; pinnedHosts: PinnedHosts; actor: AuditActorInput },
): Promise<void> {
  assertOrgParams(name, perms.routeMap)
  // Same lock and same check as every other route-map writer, so two writers cannot each pass
  // against the other's old map.
  await withRedisLock('route_maps', async () => {
    const ties = findRouteTies(name, perms.routeMap, await loadPublishedRouteRules(), ctx.pinnedHosts)
    if (ties.length > 0) throw routeTieConflict(ties)
    await redisRbacRepository.setRoles(name, perms.roles)
    await redisRbacRepository.setRouteMap(name, { rules: perms.routeMap })
    await redisRbacRepository.addService(name)
    await redisRbacRepository.setServiceMetadata(name, {
      description: ctx.description,
      createdBy: ctx.actor.email ?? undefined,
      updatedAt: new Date().toISOString(),
    })
  })
  await reconcileGroups(name, perms)
  await reconcileOrgs(name, perms)
  await rbacService.invalidateBundle('site.permissions_published', { type: 'site', id: name, service: name }, ctx.actor)
}

export async function unpublishPermissions(name: string, actor: AuditActorInput): Promise<void> {
  await reconcileGroups(name, EMPTY)
  await reconcileOrgs(name, EMPTY)
  await withRedisLock('route_maps', async () => {
    await redisRbacRepository.deleteRouteMap(name)
    await redisRbacRepository.deleteRoles(name)
    await redisRbacRepository.removeService(name)
    await redisRbacRepository.deleteServiceMetadata(name)
  })
  await rbacService.invalidateBundle('site.permissions_removed', { type: 'site', id: name, service: name }, actor)
}

async function reconcileGroups(name: string, perms: Permissions): Promise<void> {
  await withRedisLock('groups', async () => {
    const groups = await redisRbacRepository.getGroups()
    const wanted: Record<string, GroupDefinition> = { ...perms.groups.platform, ...perms.groups.orgGrantable }
    for (const [group, def] of Object.entries(wanted)) {
      const current = groups[group] ?? {}
      const next = { ...current, [name]: def[name] }
      if (JSON.stringify(current[name]) !== JSON.stringify(next[name]) || !groups[group]) {
        await redisRbacRepository.setGroup(group, next)
      }
      if (perms.groups.orgGrantable[group] && !groups[group]) {
        await redisRbacRepository.setGroupMetadata(group, { description: `Org-grantable group of site ${name}`, createdAt: new Date().toISOString() })
      }
    }
    for (const [group, def] of Object.entries(groups)) {
      if (wanted[group] || !(name in def)) continue
      const rest = Object.fromEntries(Object.entries(def).filter(([svc]) => svc !== name))
      if (Object.keys(rest).length === 0 && group.startsWith(`${name}-`)) {
        await redisRbacRepository.deleteGroup(group)
        await redisRbacRepository.deleteGroupMetadata(group)
      } else {
        await redisRbacRepository.setGroup(group, rest)
      }
    }
  })
}

async function reconcileOrgs(name: string, perms: Permissions): Promise<void> {
  await withRedisLock('org_service_map', async () => {
    const map = await redisRbacRepository.getOrgServiceMap()
    const wanted = new Set(Object.keys(perms.orgServiceMap))
    for (const org of wanted) {
      const bundle = map[org] ?? []
      if (!bundle.includes(name)) await redisRbacRepository.setOrgServiceMapping(org, [...bundle, name])
    }
    for (const [org, bundle] of Object.entries(map)) {
      if (!wanted.has(org) && bundle.includes(name)) {
        await redisRbacRepository.setOrgServiceMapping(org, bundle.filter((s) => s !== name))
      }
    }
  })
}
