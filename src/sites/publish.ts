import { redisRbacRepository, type GroupDefinition } from '../services/redis-rbac.repository.js'
import { withRedisLock } from '../services/redis-lock.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService, type AuditActorInput } from '../services/audit-event.service.js'
import { diffList } from '../services/audit-diff.js'
import { findRouteTies, loadPublishedRouteRules, routeTieConflict, type PinnedHosts } from '../policy/route-ties.js'
import { assertOrgParams } from '../policy/route-org-param.js'
import type { Rendered } from './render.js'

/**
 * A site's permissions in the keys OPA is fed from (route_map, roles, services, groups, the orgs
 * entitled to it in org_sites) — written BEFORE its gateway rules, so a new route fails closed until its
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
  await reconcileOrgs(name, perms, ctx.actor, 'published')
  await rbacService.invalidateBundle('site.permissions_published', { type: 'site', id: name, service: name }, ctx.actor)
}

export async function unpublishPermissions(name: string, actor: AuditActorInput): Promise<void> {
  await reconcileGroups(name, EMPTY)
  await reconcileOrgs(name, EMPTY, actor, 'removed')
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

/**
 * Every org bundle brought to the site's `orgs`: added where listed, and taken out of every org not
 * listed, whatever entitled it before (preview warns before:
 * findings.ts `publish_removes_orgs`). Each org's entitlements changed (rbac:org_sites) are audited
 * (org.services.changed), naming the site publish as the reason.
 */
async function reconcileOrgs(name: string, perms: Permissions, actor: AuditActorInput, why: 'published' | 'removed'): Promise<void> {
  const changed: Array<{ org: string; before: string[]; after: string[] }> = []
  await withRedisLock('org_sites', async () => {
    const map = await redisRbacRepository.getOrgSites()
    const wanted = new Set(Object.keys(perms.orgServiceMap))
    const write = async (org: string, before: string[], after: string[]) => {
      await redisRbacRepository.setOrgSites(org, after)
      changed.push({ org, before, after })
    }
    for (const org of wanted) {
      const bundle = map[org] ?? []
      if (!bundle.includes(name)) await write(org, bundle, [...bundle, name])
    }
    for (const [org, bundle] of Object.entries(map)) {
      if (!wanted.has(org) && bundle.includes(name)) await write(org, bundle, bundle.filter((s) => s !== name))
    }
  })
  const reason = why === 'published' ? `site ${name} published: its organizations are the site's orgs` : `site ${name} removed`
  for (const { org, before, after } of changed) {
    // Best-effort, like every other audit write: never fails the publish.
    Promise.resolve().then(() => auditEventService.emit({
      type: 'rbac.org_service_mapping_set',
      target: { type: 'org_sites', id: org, services: after, service: name },
      actor: { id: actor.id, email: actor.email, ip: actor.ip, name: actor.name, ua: actor.ua, sessionId: actor.sessionId, ...(actor.act ? { act: actor.act } : {}) },
      requestId: actor.requestId,
      changes: diffList('org_sites', org, before, after),
      details: { reason, site: name, via: why === 'published' ? 'site.publish' : 'site.remove' },
      source: 'jinbe-api',
    })).catch(() => {})
  }
}
