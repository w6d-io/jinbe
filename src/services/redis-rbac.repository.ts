import { getRedisClient } from './redis-client.service.js'
import { withRedisLock } from './redis-lock.js'

/**
 * Redis RBAC Repository
 *
 * Data access layer for all RBAC configuration stored in Redis.
 * Redis-backed RBAC data operations.
 *
 * Key schema:
 *   rbac:groups                    → Hash: { groupName: JSON(services) }
 *   rbac:roles:{service}           → String: JSON({ roleName: permissions[] })
 *   rbac:route_map:{service}       → String: JSON({ rules: [...] })
 *   rbac:services                  → Set: [service names]
 *   rbac:oathkeeper:rules          → String: JSON([access rule objects])
 *   rbac:config                    → Hash: { key: value }
 *   rbac:rego                      → String: raw rego policy text
 *   rbac:bundle:etag               → String: bundle version hash
 *   rbac:stats                     → String: JSON({computedAt, stats}) — directory counts, SWR (only TTL'd key)
 */

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export type GroupDefinition = Record<string, string[]> // { service: roles[] }
export type FlatRolesMap = Record<string, string[]>    // { roleName: permissions[] }
export interface RouteRule { method: string; path: string; permission?: string }
export interface RouteMap { rules: RouteRule[] }

/**
 * Per-resource metadata for groups and services. Drives RBAC-driven
 * protection: `system: true` means deletion / structural mutation requires
 * the `rbac:write_system` permission (held only by super_admin), as opposed
 * to `rbac:write` (held by regular admins).
 */
export interface ResourceMetadata {
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
  [key: string]: unknown
}

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
  // ORG → SERVICE MAP (organization UUID → RBAC service bundle)
  //
  // Storage: Redis hash rbac:org_service_map, value = JSON array of service
  // names (e.g. '["kuma","fleet"]'). An org can bundle more than one service.
  //
  // BACKWARD COMPAT: pre-migration values are a bare scalar service name
  // (e.g. 'kuma'). Service names match ^[a-z0-9_]+$ so a legacy scalar can
  // never be a JSON array literal. Reads normalize BOTH shapes to string[];
  // writes always emit the JSON array. This lets pre-migration data keep
  // serving correctly while jinbe emits arrays going forward.
  // ═══════════════════════════════════════════════════════════

  /**
   * Normalize a stored hash value to a service bundle (string[]).
   *   - new format  → JSON array of strings   → the array (filtered to strings)
   *   - legacy scalar → bare service name text → [name]
   * A value that is valid JSON but not an array (a bare number/bool/null that
   * happened to parse) is treated as a legacy scalar, not silently dropped.
   */
  private normalizeServiceBundle(raw: string): string[] {
    try {
      const parsed: unknown = JSON.parse(raw)
      if (Array.isArray(parsed)) {
        return parsed.filter((s): s is string => typeof s === 'string' && s.length > 0)
      }
      // Parsed but not an array → fall through to legacy-scalar handling.
    } catch {
      // Not JSON at all → legacy scalar service name.
    }
    return raw ? [raw] : []
  }

  async getOrgServiceMap(): Promise<Record<string, string[]>> {
    const raw = await this.redis.hgetall('rbac:org_service_map')
    const out: Record<string, string[]> = {}
    for (const [org, value] of Object.entries(raw)) {
      out[org] = this.normalizeServiceBundle(value)
    }
    return out
  }

  /**
   * The primary (first) service of an org's bundle, or the legacy scalar.
   * Returns null when the org is unmapped or its bundle is empty. Callers that
   * resolve "which service's RBAC governs this org" keep single-service
   * behaviour: a one-element bundle resolves exactly as the old scalar did.
   */
  async getServiceForOrg(organizationId: string): Promise<string | null> {
    const raw = await this.redis.hget('rbac:org_service_map', organizationId)
    if (raw === null) return null
    const bundle = this.normalizeServiceBundle(raw)
    return bundle[0] ?? null
  }

  /**
   * Replace the org's service bundle with exactly `services` (deduped, order
   * preserved). Always writes the new JSON-array format. An empty bundle
   * removes the mapping entirely (callers should prefer deleteOrgServiceMapping
   * for that intent; the route layer rejects empty bundles up front).
   */
  async setOrgServiceMapping(organizationId: string, services: string[]): Promise<void> {
    const bundle = [...new Set(services.filter(s => typeof s === 'string' && s.length > 0))]
    if (bundle.length === 0) {
      await this.redis.hdel('rbac:org_service_map', organizationId)
      return
    }
    await this.redis.hset('rbac:org_service_map', organizationId, JSON.stringify(bundle))
  }

  async deleteOrgServiceMapping(organizationId: string): Promise<boolean> {
    const deleted = await this.redis.hdel('rbac:org_service_map', organizationId)
    return deleted > 0
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
