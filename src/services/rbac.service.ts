import { kratosService } from './kratos.service.js'
import { redisRbacRepository, type GroupDefinition, type FlatRolesMap, type RouteMap, type OathkeeperRule } from './redis-rbac.repository.js'
import { auditEventService } from './audit-event.service.js'
import { env } from '../config/env.js'
import {
  DEFAULT_GROUP_SERVICE_ROLES,
  getUserGroups,
} from '../schemas/rbac/index.js'

// =============================================================================
// Helpers (kept for backward compatibility with controllers/tests)
// =============================================================================

export interface GroupsFile {
  groups: Record<string, GroupDefinition>
  emails: Record<string, unknown>
}

export function parseGroupsFile(raw: unknown): GroupsFile {
  if (!raw || typeof raw !== 'object') return { groups: {}, emails: {} }
  const obj = raw as Record<string, unknown>
  if (obj.groups && typeof obj.groups === 'object' && !Array.isArray(obj.groups)) {
    return { groups: obj.groups as Record<string, GroupDefinition>, emails: (obj.emails as Record<string, unknown>) || {} }
  }
  const groups: Record<string, GroupDefinition> = {}
  for (const [key, value] of Object.entries(obj)) {
    if (key === 'emails') continue
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      groups[key] = value as GroupDefinition
    }
  }
  return { groups, emails: (obj.emails as Record<string, unknown>) || {} }
}

export function parseRolesContent(raw: unknown): Array<{ name: string; permissions: string[]; description?: string; inherits?: string[] }> {
  if (!raw || typeof raw !== 'object') return []
  const obj = raw as Record<string, unknown>
  if (Array.isArray(obj.roles)) {
    return obj.roles as Array<{ name: string; permissions: string[]; description?: string; inherits?: string[] }>
  }
  const roles: Array<{ name: string; permissions: string[] }> = []
  for (const [key, value] of Object.entries(obj)) {
    if (key === 'version' || key === 'service') continue
    if (Array.isArray(value)) roles.push({ name: key, permissions: value as string[] })
  }
  return roles
}

// =============================================================================
// Types
// =============================================================================

export interface UserWithGroups {
  email: string
  name?: string
  groupMembership: Record<string, boolean>
}

export interface GroupInfo {
  name: string
  services: GroupDefinition
}

export interface UsersResponse {
  users: UserWithGroups[]
}

export interface GroupsResponse {
  groups: GroupInfo[]
}

export interface ServiceInfo {
  name: string
  rolesCount: number
  routesCount: number
}

export interface ServicesResponse {
  services: ServiceInfo[]
}

export interface CreateServiceOptions {
  name: string
  displayName?: string
  upstreamUrl?: string
  matchUrl?: string
  matchMethods?: string[]
}

export interface AccessRulesResponse {
  rules: OathkeeperRule[]
}

export interface MutationResult {
  success: boolean
  message: string
  timestamp: string
}

export interface KratosBindingsResponse {
  emails: Record<string, unknown>
  group_membership: Record<string, string[]>
}

// Re-export types from repository for convenience
export type { GroupDefinition, FlatRolesMap, RouteMap, OathkeeperRule }

// =============================================================================
// RBAC Service — Redis-backed
// =============================================================================

export class RbacService {
  // ===========================================================================
  // Private Helpers
  // ===========================================================================

  private result(message: string): MutationResult {
    return { success: true, message, timestamp: new Date().toISOString() }
  }

  private async invalidateBundle(eventType?: string, target?: { type?: string; id?: string; service?: string }, actor?: { email?: string; ip?: string }): Promise<void> {
    await redisRbacRepository.invalidateBundleEtag()

    // Notify OPAL server for real-time WebSocket push to all OPA clients (<100ms)
    this.notifyOpal(eventType).catch(() => {})

    if (eventType) {
      auditEventService.emit({ type: eventType, target, actor, source: 'jinbe-api' }).catch(() => {})
    }
  }

  private async notifyOpal(reason?: string): Promise<void> {
    try {
      const jinbeUrl = env.JINBE_INTERNAL_URL || 'http://jinbe.w6d-ops:8080'

      await fetch(`${env.OPAL_SERVER_URL}/data/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entries: [
            { url: `${jinbeUrl}/api/admin/rbac/bindings`, topics: ['policy_data'], dst_path: '/bindings' },
            { url: `${jinbeUrl}/api/admin/rbac/opal/groups`, topics: ['policy_data'], dst_path: '/bindings/groups' },
          ],
          reason: reason || 'rbac-mutation',
        }),
      })
      console.log(`[opal-notify] Triggered: ${reason || 'rbac-mutation'}`)
    } catch (err) {
      console.error('[opal-notify] Failed:', err)
    }
  }

  private async notifyOpalRoles(serviceName: string): Promise<void> {
    try {
      const jinbeUrl = env.JINBE_INTERNAL_URL || 'http://jinbe.w6d-ops:8080'
      await fetch(`${env.OPAL_SERVER_URL}/data/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entries: [
            { url: `${jinbeUrl}/api/admin/rbac/opal/roles/${serviceName}`, topics: ['policy_data'], dst_path: `/roles/${serviceName}` },
          ],
          reason: `roles.updated.${serviceName}`,
        }),
      })
    } catch (err) {
      console.error('[opal-notify-roles] Failed:', err)
    }
  }

  // ===========================================================================
  // Users & Bindings
  // ===========================================================================

  async getUsers(): Promise<UsersResponse> {
    const bindings = await this.getBindingsFromKratos()
    const groups = await redisRbacRepository.getGroups()
    const groupNames = Object.keys(groups)

    const users: UserWithGroups[] = []

    for (const [email, membership] of Object.entries(bindings.group_membership)) {
      const userGroups = getUserGroups(membership)
      const groupMembership: Record<string, boolean> = {}
      for (const groupName of groupNames) {
        groupMembership[groupName] = userGroups.includes(groupName)
      }
      users.push({ email, groupMembership })
    }

    // Enrich with names from Kratos
    try {
      const kratosResponse = await kratosService.listIdentities()
      const emailToName = new Map<string, string | undefined>(
        kratosResponse.identities.map((u) => {
          const displayName = u.traits.name || undefined
          return [u.traits.email as string, displayName]
        })
      )
      for (const user of users) {
        user.name = emailToName.get(user.email)
      }
    } catch { /* Kratos unavailable */ }

    return { users }
  }

  // ===========================================================================
  // Groups
  // ===========================================================================

  async getGroups(): Promise<GroupsResponse> {
    const groups = await redisRbacRepository.getGroups()
    const groupsInfo: GroupInfo[] = Object.entries(groups).map(([name, services]) => ({ name, services }))
    return { groups: groupsInfo }
  }

  async createGroup(name: string, services: GroupDefinition, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (await redisRbacRepository.groupExists(name)) {
      throw Object.assign(new Error(`Group already exists: ${name}`), { statusCode: 409 })
    }
    await redisRbacRepository.setGroup(name, services)
    await this.invalidateBundle('rbac.group_created', { type: 'group', id: name }, actor)
    return this.result(`Group '${name}' created`)
  }

  async updateGroup(name: string, services: GroupDefinition, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (!(await redisRbacRepository.groupExists(name))) {
      throw Object.assign(new Error(`Group not found: ${name}`), { statusCode: 404 })
    }
    await redisRbacRepository.setGroup(name, services)
    await this.invalidateBundle('rbac.group_updated', { type: 'group', id: name }, actor)
    return this.result(`Group '${name}' updated`)
  }

  async deleteGroup(name: string, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (!(await redisRbacRepository.groupExists(name))) {
      throw Object.assign(new Error(`Group not found: ${name}`), { statusCode: 404 })
    }
    await redisRbacRepository.deleteGroup(name)

    // Cascade: remove group from all Kratos users
    try {
      const usersUpdated = await kratosService.removeGroupFromAllUsers(name)
      if (usersUpdated > 0) {
        console.log(`[rbac] Removed group '${name}' from ${usersUpdated} Kratos users`)
      }
    } catch (error) {
      console.error(`[rbac] Failed to remove group '${name}' from Kratos users:`, error)
    }

    await this.invalidateBundle('rbac.group_deleted', { type: 'group', id: name }, actor)
    return this.result(`Group '${name}' deleted`)
  }

  // ===========================================================================
  // Group Validation
  // ===========================================================================

  async getAvailableGroups(): Promise<string[]> {
    const groups = await redisRbacRepository.getGroups()
    return Object.keys(groups)
  }

  async validateGroups(groups: string[]): Promise<void> {
    const available = await this.getAvailableGroups()
    const invalid = groups.filter(g => !available.includes(g))
    if (invalid.length > 0) {
      throw new Error(`Invalid groups: ${invalid.join(', ')}. Available: ${available.join(', ')}`)
    }
  }

  // ===========================================================================
  // Services
  // ===========================================================================

  async getServices(): Promise<ServicesResponse> {
    const serviceNames = await redisRbacRepository.getServices()
    const services: ServiceInfo[] = []

    for (const name of serviceNames) {
      const roles = await redisRbacRepository.getRoles(name)
      const routeMap = await redisRbacRepository.getRouteMap(name)
      services.push({
        name,
        rolesCount: roles ? Object.keys(roles).length : 0,
        routesCount: routeMap?.rules?.length || 0,
      })
    }

    return { services }
  }

  async createService(options: CreateServiceOptions, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    const { name } = options

    if (await redisRbacRepository.serviceExists(name)) {
      throw Object.assign(new Error(`Service already exists: ${name}`), { statusCode: 409 })
    }

    const namespace = env.SERVICE_DEFAULT_NAMESPACE
    const domain = env.SERVICE_DEFAULT_DOMAIN
    const port = env.SERVICE_DEFAULT_PORT

    const upstreamUrl = options.upstreamUrl || `http://${name}.${namespace}:${port}`
    const matchUrl = options.matchUrl || `https://${domain}/api/${name}/<**>`
    const healthMatchUrl = options.matchUrl
      ? options.matchUrl.replace(/<\*\*>$/, 'health')
      : `https://${domain}/api/${name}/health`
    const matchMethods = options.matchMethods || ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']

    // 1. Create default roles
    const defaultRoles: FlatRolesMap = {
      admin: ['*'],
      operator: [`${name}:list`, `${name}:read`, `${name}:create`, `${name}:update`, `${name}:delete`, `${name}:execute`],
      editor: [`${name}:list`, `${name}:read`, `${name}:create`, `${name}:update`],
      viewer: [`${name}:list`, `${name}:read`],
    }

    // 2. Create default route map with health endpoint
    const defaultRouteMap: RouteMap = {
      rules: [{ method: 'GET', path: `/api/${name}/health` }],
    }

    // 3. Create Oathkeeper rules
    const mainRule: OathkeeperRule = {
      id: name,
      upstream: { url: upstreamUrl },
      match: { url: matchUrl, methods: matchMethods },
      authenticators: [{ handler: 'cookie_session' }],
      authorizer: { handler: 'remote_json' },
      mutators: [{ handler: 'header' }],
    }

    const healthRule: OathkeeperRule = {
      id: `${name}-health`,
      upstream: { url: `${upstreamUrl}health` },
      match: { url: healthMatchUrl, methods: ['GET', 'OPTIONS'] },
      authenticators: [{ handler: 'noop' }],
      authorizer: { handler: 'allow' },
      mutators: [{ handler: 'noop' }],
    }

    // 4. Write all to Redis
    await redisRbacRepository.addService(name)
    await redisRbacRepository.setRoles(name, defaultRoles)
    await redisRbacRepository.setRouteMap(name, defaultRouteMap)

    // Add oathkeeper rules
    try { await redisRbacRepository.addAccessRule(mainRule) } catch { /* already exists */ }
    try { await redisRbacRepository.addAccessRule(healthRule) } catch { /* already exists */ }

    // 5. Auto-populate standard groups with default roles
    const groups = await redisRbacRepository.getGroups()
    for (const [groupName, defaultGroupRoles] of Object.entries(DEFAULT_GROUP_SERVICE_ROLES)) {
      if (groups[groupName]) {
        groups[groupName][name] = defaultGroupRoles
        await redisRbacRepository.setGroup(groupName, groups[groupName])
      }
    }

    await this.invalidateBundle('rbac.service_created', { type: 'service', id: name }, actor)
    return this.result(`Service '${name}' created with roles, routes, and oathkeeper rules`)
  }

  async deleteService(name: string, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(name))) {
      throw Object.assign(new Error(`Service not found: ${name}`), { statusCode: 404 })
    }

    // Remove from all groups
    const groups = await redisRbacRepository.getGroups()
    for (const [groupName, services] of Object.entries(groups)) {
      if (name in services) {
        delete services[name]
        await redisRbacRepository.setGroup(groupName, services)
      }
    }

    // Remove oathkeeper rules
    await redisRbacRepository.deleteAccessRule(name)
    await redisRbacRepository.deleteAccessRule(`${name}-health`)

    // Remove data
    await redisRbacRepository.deleteRoles(name)
    await redisRbacRepository.deleteRouteMap(name)
    await redisRbacRepository.removeService(name)

    await this.invalidateBundle('rbac.service_deleted', { type: 'service', id: name }, actor)
    return this.result(`Service '${name}' deleted`)
  }

  async updateServiceRoutes(serviceName: string, rules: RouteMap['rules'], actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(serviceName))) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    await redisRbacRepository.setRouteMap(serviceName, { rules })
    await this.invalidateBundle('rbac.service_routes_updated', { type: 'service', id: serviceName }, actor)
    return this.result(`Route map for '${serviceName}' updated (${rules.length} rules)`)
  }

  async getServiceRoutes(serviceName: string): Promise<{ service: string; rules: RouteMap['rules'] }> {
    if (!(await redisRbacRepository.serviceExists(serviceName))) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    const routeMap = await redisRbacRepository.getRouteMap(serviceName)
    return { service: serviceName, rules: routeMap?.rules ?? [] }
  }

  async updateServiceRoles(
    serviceName: string,
    roles: Record<string, string[]>,
    actor?: { email?: string; ip?: string }
  ): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(serviceName))) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    await redisRbacRepository.setRoles(serviceName, roles)
    this.notifyOpalRoles(serviceName).catch(() => {})
    await this.invalidateBundle('roles.updated', { type: 'service', id: serviceName, service: serviceName }, actor)
    return this.result(`Roles updated for ${serviceName}`)
  }

  async getServiceRoles(serviceName: string): Promise<{ service: string; roles: Array<{ name: string; permissions: string[] }> }> {
    const roles = await redisRbacRepository.getRoles(serviceName)
    if (!roles) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    return {
      service: serviceName,
      roles: Object.entries(roles).map(([name, permissions]) => ({ name, permissions })),
    }
  }

  // ===========================================================================
  // Access Rules (Oathkeeper)
  // ===========================================================================

  async getAccessRules(): Promise<AccessRulesResponse> {
    const rules = await redisRbacRepository.getAccessRules()
    return { rules }
  }

  async getAccessRule(id: string): Promise<{ rule: OathkeeperRule }> {
    const rule = await redisRbacRepository.getAccessRule(id)
    if (!rule) {
      throw Object.assign(new Error(`Access rule not found: ${id}`), { statusCode: 404 })
    }
    return { rule }
  }

  async createAccessRule(rule: OathkeeperRule, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    try {
      await redisRbacRepository.addAccessRule(rule)
    } catch (err) {
      throw Object.assign(new Error((err as Error).message), { statusCode: 409 })
    }
    await this.invalidateBundle('rbac.access_rule_created', { type: 'access_rule', id: rule.id }, actor)
    return this.result(`Access rule '${rule.id}' created`)
  }

  async updateAccessRule(id: string, rule: OathkeeperRule, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    const updated = await redisRbacRepository.updateAccessRule(id, { ...rule, id })
    if (!updated) {
      throw Object.assign(new Error(`Access rule not found: ${id}`), { statusCode: 404 })
    }
    await this.invalidateBundle('rbac.access_rule_updated', { type: 'access_rule', id }, actor)
    return this.result(`Access rule '${id}' updated`)
  }

  async deleteAccessRule(id: string, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    const deleted = await redisRbacRepository.deleteAccessRule(id)
    if (!deleted) {
      throw Object.assign(new Error(`Access rule not found: ${id}`), { statusCode: 404 })
    }
    await this.invalidateBundle('rbac.access_rule_deleted', { type: 'access_rule', id }, actor)
    return this.result(`Access rule '${id}' deleted`)
  }

  // ===========================================================================
  // Kratos Bindings
  // ===========================================================================

  async getBindingsFromKratos(): Promise<KratosBindingsResponse> {
    const identitiesWithGroups = await kratosService.getAllIdentitiesWithGroups()
    const group_membership: Record<string, string[]> = {}
    for (const [email, groups] of identitiesWithGroups) {
      group_membership[email] = groups
    }
    return { emails: {}, group_membership }
  }
}

// Singleton export
export const rbacService = new RbacService()
