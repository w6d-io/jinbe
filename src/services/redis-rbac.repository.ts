import { getRedisClient } from './redis-client.service.js'

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
 */

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export type GroupDefinition = Record<string, string[]> // { service: roles[] }
export type FlatRolesMap = Record<string, string[]>    // { roleName: permissions[] }
export interface RouteRule { method: string; path: string; permission?: string }
export interface RouteMap { rules: RouteRule[] }
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

  async addAccessRule(rule: OathkeeperRule): Promise<void> {
    const rules = await this.getAccessRules()
    if (rules.some(r => r.id === rule.id)) {
      throw new Error(`Access rule '${rule.id}' already exists`)
    }
    rules.push(rule)
    await this.setAccessRules(rules)
  }

  async updateAccessRule(id: string, rule: OathkeeperRule): Promise<boolean> {
    const rules = await this.getAccessRules()
    const idx = rules.findIndex(r => r.id === id)
    if (idx === -1) return false
    rules[idx] = rule
    await this.setAccessRules(rules)
    return true
  }

  async deleteAccessRule(id: string): Promise<boolean> {
    const rules = await this.getAccessRules()
    const filtered = rules.filter(r => r.id !== id)
    if (filtered.length === rules.length) return false
    await this.setAccessRules(filtered)
    return true
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
