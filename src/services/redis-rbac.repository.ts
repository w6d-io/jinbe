import { getRedisClient } from './redis-client.service.js'
import { withRedisLock } from './redis-lock.js'

/**
 * Redis RBAC Repository
 *
 * Data access layer for all RBAC configuration stored in Redis.
 * Redis-backed RBAC data operations.
 *
 * Key schema:
 *   rbac:groups                    → Hash: { groupName: JSON({ app: roles[] }) }
 *   rbac:roles:{service}           → String: JSON({ roleName: permissions[] })  platform roles, no `*`
 *   rbac:org_roles:{service}       → String: JSON({ roleName: org permissions[] })
 *   rbac:every_org:{service}       → String: JSON({ platform role: org permissions[] })
 *   rbac:org_sites                 → Hash: { organizationId: JSON([site]) }
 *   rbac:org_assignments           → Hash: { organizationId: JSON({ subjectId: ["svc:role"] }) }
 *   rbac:owned:{owner}             → String: JSON({ key: sha256 }) — what code last wrote (drift)
 *   rbac:break_glass               → String: JSON(BreakGlassGrant) — the one emergency path
 *   rbac:route_map:{service}       → String: JSON({ rules: [...] })
 *   rbac:services                  → Set: [service names]
 *   rbac:oathkeeper:rules          → String: JSON([access rule objects])
 *   rbac:config                    → Hash: { key: value }
 *   rbac:rego                      → String: raw rego policy text
 *   rbac:bundle:etag               → String: bundle version hash
 *   rbac:stats                     → String: JSON({computedAt, stats}) — directory counts, SWR (only TTL'd key)
 *   rbac:import:history            → List: JSON({id, takenAt, actor, reason, bundle}) — pre-import/restore/rollback
 *                                    snapshots (LPUSH newest-first, LTRIM cap 10) for quick rollback
 *   rbac:scim:tokens               → Hash: { tokenId: JSON({sha256, label, createdBy, createdAt, lastUsedAt}) }
 *                                    — SCIM bearer tokens, hashed at rest (scim-token.service)
 *   rbac:recert:campaigns          → Hash: { campaignId: JSON(RecertCampaign) } — access-recertification
 *   rbac:recert:items:{campaignId} → Hash: { itemId: JSON(RecertItem) }         campaigns (redis-recert.repository);
 *   rbac:recert:inbox:{reviewer}   → Set:  [ "{campaignId}:{itemId}" ]          inbox = inverse reviewer index;
 *   rbac:recert:reports            → Hash: { campaignId: JSON(RecertReport) }   reports frozen at close (no TTL)
 */

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export type GroupDefinition = Record<string, string[]> // { service: roles[] }
export type FlatRolesMap = Record<string, string[]>    // { roleName: permissions[] }
// org_param: name of the `:param` in `path` that carries the org id — the route is then that org's
// only (opal-policies org.rego). Checked by policy/route-org-param.ts before any write.
/** `id`: the Site route a row comes from (data.site_login routes name rows by it); absent on non-site rows. */
/** `public: true` marks a route open to anyone: per-site 2FA (opal-policies step_up_required) never gates it. */
export interface RouteRule {
  id?: string; method: string; path: string; permission?: string; org_param?: string; public?: boolean
  /** `any_org`: the (org) permission held in ANY organisation reaches the route; the route's own guard narrows to those orgs. */
  scope?: 'any_org'
}
export interface RouteMap { rules: RouteRule[] }

/** Per-resource metadata for groups and services (description, who and when). */
export interface ResourceMetadata {
  /** Written by code (jinbe) or a site intent: not editable through the API. */
  system?: boolean
  description?: string
  createdBy?: string
  createdAt?: string
  updatedAt?: string
}
export interface OathkeeperRule {
  id: string
  upstream: { url: string; preserve_host?: boolean; strip_path?: string }
  match: { url: string; methods: string[] }
  authenticators: Array<{ handler: string; config?: unknown }>
  authorizer: { handler: string; config?: unknown }
  mutators: Array<{ handler: string; config?: unknown }>
  // Optional error handlers — what a denied/failed request receives (e.g.
  // redirect to login vs. a JSON error). First-class so it round-trips through
  // create/update and is served to Oathkeeper unchanged.
  errors?: Array<{ handler: string; config?: unknown }>
  [key: string]: unknown
}

/**
 * A pre-apply snapshot of the whole RBAC config, taken before every bundle
 * import/restore/rollback. `bundle` is a full AuthBundle (typed loosely here —
 * the AuthBundle type lives in rbac-bundle.service, which imports this module).
 */
export type ImportHistoryReason = 'pre-import' | 'pre-restore' | 'pre-rollback'
export interface ImportHistoryEntry {
  id: string
  takenAt: string
  actor: string | null
  reason: ImportHistoryReason
  bundle: unknown
}

const IMPORT_HISTORY_KEY = 'rbac:import:history'
const IMPORT_HISTORY_CAP = 10

// ─────────────────────────────────────────────────────────────
// Repository
// ─────────────────────────────────────────────────────────────

class RedisRbacRepository {
  private get redis() { return getRedisClient() }

  // ═══════════════════════════════════════════════════════════
  // GROUPS
  // ═══════════════════════════════════════════════════════════

  async getGroups(): Promise<Record<string, GroupDefinition>> {
    const raw = await this.redis.hgetall('rbac:groups')
    const groups: Record<string, GroupDefinition> = {}
    for (const [name, json] of Object.entries(raw)) {
      groups[name] = JSON.parse(json)
    }
    return groups
  }

  async getGroup(name: string): Promise<GroupDefinition | null> {
    const raw = await this.redis.hget('rbac:groups', name)
    return raw ? JSON.parse(raw) : null
  }

  async setGroup(name: string, services: GroupDefinition): Promise<void> {
    await this.redis.hset('rbac:groups', name, JSON.stringify(services))
  }

  async deleteGroup(name: string): Promise<boolean> {
    const deleted = await this.redis.hdel('rbac:groups', name)
    return deleted > 0
  }

  async groupExists(name: string): Promise<boolean> {
    const raw = await this.redis.hget('rbac:groups', name)
    return raw !== null
  }

  // ═══════════════════════════════════════════════════════════
  // GROUP METADATA (system flag, description, audit)
  // ═══════════════════════════════════════════════════════════

  async getGroupMetadata(name: string): Promise<ResourceMetadata | null> {
    const raw = await this.redis.hget('rbac:groups:meta', name)
    return raw ? JSON.parse(raw) : null
  }

  async setGroupMetadata(name: string, meta: ResourceMetadata): Promise<void> {
    await this.redis.hset('rbac:groups:meta', name, JSON.stringify(meta))
  }

  async deleteGroupMetadata(name: string): Promise<void> {
    await this.redis.hdel('rbac:groups:meta', name)
  }

  async getAllGroupMetadata(): Promise<Record<string, ResourceMetadata>> {
    const raw = await this.redis.hgetall('rbac:groups:meta')
    const out: Record<string, ResourceMetadata> = {}
    for (const [name, json] of Object.entries(raw)) {
      out[name] = JSON.parse(json)
    }
    return out
  }

  // ═══════════════════════════════════════════════════════════
  // SERVICE METADATA (system flag, description)
  // ═══════════════════════════════════════════════════════════

  async getServiceMetadata(name: string): Promise<ResourceMetadata | null> {
    const raw = await this.redis.hget('rbac:services:meta', name)
    return raw ? JSON.parse(raw) : null
  }

  async setServiceMetadata(name: string, meta: ResourceMetadata): Promise<void> {
    await this.redis.hset('rbac:services:meta', name, JSON.stringify(meta))
  }

  async deleteServiceMetadata(name: string): Promise<void> {
    await this.redis.hdel('rbac:services:meta', name)
  }

  async getAllServiceMetadata(): Promise<Record<string, ResourceMetadata>> {
    const raw = await this.redis.hgetall('rbac:services:meta')
    const out: Record<string, ResourceMetadata> = {}
    for (const [name, json] of Object.entries(raw)) {
      out[name] = JSON.parse(json)
    }
    return out
  }

  // ═══════════════════════════════════════════════════════════
  // ROLES (per service)
  // ═══════════════════════════════════════════════════════════

  async getRoles(service: string): Promise<FlatRolesMap | null> {
    const raw = await this.redis.get(`rbac:roles:${service}`)
    return raw ? JSON.parse(raw) : null
  }

  async setRoles(service: string, roles: FlatRolesMap): Promise<void> {
    await this.redis.set(`rbac:roles:${service}`, JSON.stringify(roles))
  }

  async deleteRoles(service: string): Promise<boolean> {
    const deleted = await this.redis.del(`rbac:roles:${service}`)
    return deleted > 0
  }

  // ═══════════════════════════════════════════════════════════
  // SERVICES (registry)
  // ═══════════════════════════════════════════════════════════

  async getServices(): Promise<string[]> {
    return this.redis.smembers('rbac:services')
  }

  async addService(name: string): Promise<void> {
    await this.redis.sadd('rbac:services', name)
  }

  async removeService(name: string): Promise<void> {
    await this.redis.srem('rbac:services', name)
  }

  async serviceExists(name: string): Promise<boolean> {
    const result = await this.redis.sismember('rbac:services', name)
    return result === 1
  }

  // ═══════════════════════════════════════════════════════════
  // ROUTE MAPS (per service)
  // ═══════════════════════════════════════════════════════════

  async getRouteMap(service: string): Promise<RouteMap | null> {
    const raw = await this.redis.get(`rbac:route_map:${service}`)
    return raw ? JSON.parse(raw) : null
  }

  async setRouteMap(service: string, routeMap: RouteMap): Promise<void> {
    await this.redis.set(`rbac:route_map:${service}`, JSON.stringify(routeMap))
  }

  async deleteRouteMap(service: string): Promise<boolean> {
    const deleted = await this.redis.del(`rbac:route_map:${service}`)
    return deleted > 0
  }

  // ═══════════════════════════════════════════════════════════
  // OATHKEEPER ACCESS RULES
  // ═══════════════════════════════════════════════════════════

  async getAccessRules(): Promise<OathkeeperRule[]> {
    const raw = await this.redis.get('rbac:oathkeeper:rules')
    return raw ? JSON.parse(raw) : []
  }

  async setAccessRules(rules: OathkeeperRule[]): Promise<void> {
    await this.redis.set('rbac:oathkeeper:rules', JSON.stringify(rules))
  }

  async getAccessRule(id: string): Promise<OathkeeperRule | null> {
    const rules = await this.getAccessRules()
    return rules.find(r => r.id === id) || null
  }

  // All access-rule mutations are a read-modify-write on the single
  // `rbac:oathkeeper:rules` blob, so they MUST serialize under one lock —
  // otherwise two concurrent admins each read the same array and the last SET
  // clobbers the other's rule (a created rule silently vanishes despite a 200,
  // leaving a service unrouted). See audit finding #7. The service-layer
  // updateServiceConfig takes the SAME lock name.
  async addAccessRule(rule: OathkeeperRule): Promise<void> {
    return withRedisLock('oathkeeper:rules', async () => {
      const rules = await this.getAccessRules()
      if (rules.some(r => r.id === rule.id)) {
        throw new Error(`Access rule '${rule.id}' already exists`)
      }
      rules.push(rule)
      await this.setAccessRules(rules)
    })
  }

  async updateAccessRule(id: string, rule: OathkeeperRule): Promise<boolean> {
    return withRedisLock('oathkeeper:rules', async () => {
      const rules = await this.getAccessRules()
      const idx = rules.findIndex(r => r.id === id)
      if (idx === -1) return false
      rules[idx] = rule
      await this.setAccessRules(rules)
      return true
    })
  }

  async deleteAccessRule(id: string): Promise<boolean> {
    return withRedisLock('oathkeeper:rules', async () => {
      const rules = await this.getAccessRules()
      const filtered = rules.filter(r => r.id !== id)
      if (filtered.length === rules.length) return false
      await this.setAccessRules(filtered)
      return true
    })
  }

  // ═══════════════════════════════════════════════════════════
  // IMPORT HISTORY (pre-apply snapshots for quick rollback)
  //
  // Every import/restore/rollback pushes a full pre-apply snapshot here
  // (newest first). Capped at 10 entries so a runaway restore loop can't
  // grow the key unboundedly — an entry embeds the whole AuthBundle.
  // ═══════════════════════════════════════════════════════════

  async pushImportHistory(entry: ImportHistoryEntry): Promise<void> {
    await this.redis.lpush(IMPORT_HISTORY_KEY, JSON.stringify(entry))
    await this.redis.ltrim(IMPORT_HISTORY_KEY, 0, IMPORT_HISTORY_CAP - 1)
  }

  async getImportHistory(): Promise<ImportHistoryEntry[]> {
    const raw = await this.redis.lrange(IMPORT_HISTORY_KEY, 0, -1)
    return raw.map((json) => JSON.parse(json))
  }

  async getImportHistoryEntry(id: string): Promise<ImportHistoryEntry | null> {
    const entries = await this.getImportHistory()
    return entries.find((e) => e.id === id) ?? null
  }

  // ═══════════════════════════════════════════════════════════
  // CONFIG
  // ═══════════════════════════════════════════════════════════

  async getConfig(): Promise<Record<string, string>> {
    return this.redis.hgetall('rbac:config')
  }

  async setConfig(key: string, value: string): Promise<void> {
    await this.redis.hset('rbac:config', key, value)
  }

  // ═══════════════════════════════════════════════════════════
  // REGO POLICY
  // ═══════════════════════════════════════════════════════════

  async getRego(): Promise<string | null> {
    return this.redis.get('rbac:rego')
  }

  async setRego(text: string): Promise<void> {
    await this.redis.set('rbac:rego', text)
  }

  // ═══════════════════════════════════════════════════════════
  // BUNDLE ETAG (for OPA polling efficiency)
  // ═══════════════════════════════════════════════════════════

  async getBundleEtag(): Promise<string | null> {
    return this.redis.get('rbac:bundle:etag')
  }

  async setBundleEtag(etag: string): Promise<void> {
    await this.redis.set('rbac:bundle:etag', etag)
  }

  async invalidateBundleEtag(): Promise<string> {
    const etag = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    await this.setBundleEtag(etag)
    return etag
  }

  // ═══════════════════════════════════════════════════════════
  // STATS CACHE (directory counts — total/active/perGroup/perOrg)
  // The only TTL'd key in this repo: a safety net so counts can't go
  // unboundedly stale if the app dies. Freshness is decided in rbac.service
  // from the payload's computedAt (stale-while-revalidate).
  // ═══════════════════════════════════════════════════════════

  async getStats(): Promise<string | null> {
    return this.redis.get('rbac:stats')
  }

  async setStats(json: string, ttlSeconds: number): Promise<void> {
    await this.redis.set('rbac:stats', json, 'EX', ttlSeconds)
  }

  async invalidateStats(): Promise<void> {
    await this.redis.del('rbac:stats')
  }

  // ═══════════════════════════════════════════════════════════
  // ORGANISATIONS: entitlements, org role definitions, every-org map
  //
  //   rbac:org_sites          Hash: { organizationId: JSON([site, …]) }  sites an org is entitled to
  //                           (written by site intents). Published as data.org_sites with `jinbe`
  //                           added for every known org.
  //   rbac:org_roles:{svc}    JSON({ role: [org permission] })            org roles (code for jinbe,
  //                           the site intent for a site)
  //   rbac:every_org:{app}    JSON({ role: [org permission] })            what a platform role carries
  //                           into every org (the only such path, design §2.4)
  //   rbac:org_owner_roles    Hash: { site: role }                        the org role an org's owners
  //                           hold on a site with organizations on (its intent's ownerRole)
  //
  // Who holds which org role in which org lives in rbac:org_assignments (org-roles.repository.ts).
  // ═══════════════════════════════════════════════════════════

  async getOrgSites(): Promise<Record<string, string[]>> {
    const raw = await this.redis.hgetall('rbac:org_sites')
    const out: Record<string, string[]> = {}
    for (const [org, value] of Object.entries(raw)) {
      try {
        const parsed: unknown = JSON.parse(value)
        if (Array.isArray(parsed)) out[org] = parsed.filter((s): s is string => typeof s === 'string' && s.length > 0)
      } catch { /* a malformed entry entitles nothing */ }
    }
    return out
  }

  /** Exactly these sites for one org; an empty list removes the entry. */
  async setOrgSites(organizationId: string, sites: string[]): Promise<void> {
    const list = [...new Set(sites.filter((s) => typeof s === 'string' && s.length > 0))].sort()
    if (list.length === 0) await this.redis.hdel('rbac:org_sites', organizationId)
    else await this.redis.hset('rbac:org_sites', organizationId, JSON.stringify(list))
  }

  async getOrgRoles(service: string): Promise<FlatRolesMap | null> {
    const raw = await this.redis.get(`rbac:org_roles:${service}`)
    return raw ? JSON.parse(raw) : null
  }

  async setOrgRoles(service: string, roles: FlatRolesMap): Promise<void> {
    await this.redis.set(`rbac:org_roles:${service}`, JSON.stringify(roles))
  }

  async deleteOrgRoles(service: string): Promise<void> {
    await this.redis.del(`rbac:org_roles:${service}`)
  }

  async getEveryOrg(service: string): Promise<FlatRolesMap | null> {
    const raw = await this.redis.get(`rbac:every_org:${service}`)
    return raw ? JSON.parse(raw) : null
  }

  async setEveryOrg(service: string, map: FlatRolesMap): Promise<void> {
    await this.redis.set(`rbac:every_org:${service}`, JSON.stringify(map))
  }

  async deleteEveryOrg(service: string): Promise<void> {
    await this.redis.del(`rbac:every_org:${service}`)
  }

  /** site → the org role an organisation's owners hold there (sites with organizations on). */
  async getOrgOwnerRoles(): Promise<Record<string, string>> {
    const raw = await this.redis.hgetall('rbac:org_owner_roles')
    return Object.fromEntries(Object.entries(raw).filter(([, role]) => typeof role === 'string' && role.length > 0))
  }

  /** null removes the site's entry (organizations off, or no owner role). */
  async setOrgOwnerRole(service: string, role: string | null): Promise<void> {
    if (role) await this.redis.hset('rbac:org_owner_roles', service, role)
    else await this.redis.hdel('rbac:org_owner_roles', service)
  }

  // ═══════════════════════════════════════════════════════════
  // BULK: Get all RBAC data for OPA bundle
  // ═══════════════════════════════════════════════════════════

  async getAllForBundle(): Promise<{
    groups: Record<string, GroupDefinition>
    roles: Record<string, FlatRolesMap>
    routeMaps: Record<string, RouteMap>
  }> {
    const groups = await this.getGroups()
    const services = await this.getServices()

    const roles: Record<string, FlatRolesMap> = {}
    const routeMaps: Record<string, RouteMap> = {}

    for (const svc of services) {
      const r = await this.getRoles(svc)
      if (r) roles[svc] = r
      const rm = await this.getRouteMap(svc)
      if (rm) routeMaps[svc] = rm
    }

    return { groups, roles, routeMaps }
  }
}

export const redisRbacRepository = new RedisRbacRepository()
