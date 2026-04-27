import { kratosService, KratosApiError } from './kratos.service.js'
import { redisRbacRepository, type FlatRolesMap } from './redis-rbac.repository.js'

/**
 * Resolved RBAC info for a user
 */
export interface ResolvedUserRbac {
  email: string
  groups: string[]
  roles: string[]
  permissions: string[]
}

type FlatGroupsMap = Record<string, Record<string, string[]>>

/**
 * RbacResolverService
 *
 * Resolves the RBAC chain from Redis:
 * User → Kratos (groups) → Redis (group definitions) → Redis (role definitions) → Permissions
 *
 * Matches Rego policy logic exactly:
 * - user_roles_for_app: groups → global roles + service-specific roles
 * - user_permissions: roles → permissions (from both global and service role definitions)
 */
class RbacResolverService {
  /**
   * Resolve full RBAC info for a user
   */
  async resolveUserRbac(email: string, appName: string): Promise<ResolvedUserRbac> {
    // 1. Get user's groups from Kratos
    let groups: string[]
    try {
      groups = await kratosService.getUserGroups(email)
    } catch (error) {
      if (error instanceof KratosApiError && error.statusCode === 404) {
        groups = ['users']
      } else {
        console.error(`[rbac-resolver] Failed to get groups for ${email}:`, error)
        groups = ['users']
      }
    }

    // 2. Get group definitions from Redis
    const groupsDef = await redisRbacRepository.getGroups()

    // 3. Resolve roles from groups
    const roles = this.resolveRoles(groups, groupsDef, appName)

    // 4. Get role definitions from Redis
    const [serviceRolesDef, globalRolesDef] = await Promise.all([
      redisRbacRepository.getRoles(appName),
      redisRbacRepository.getRoles('global'),
    ])

    // 5. Resolve permissions from roles
    const permissions = this.resolvePermissions(roles, serviceRolesDef, globalRolesDef)

    return {
      email,
      groups,
      roles: Array.from(roles),
      permissions: Array.from(permissions),
    }
  }

  private resolveRoles(
    groups: string[],
    groupsDef: FlatGroupsMap,
    appName: string
  ): Set<string> {
    const roles = new Set<string>()

    for (const groupName of groups) {
      const groupDef = groupsDef[groupName]
      if (!groupDef) continue

      const globalRoles = groupDef['global']
      if (globalRoles && Array.isArray(globalRoles)) {
        globalRoles.forEach(role => roles.add(role))
      }

      const serviceRoles = groupDef[appName]
      if (serviceRoles && Array.isArray(serviceRoles)) {
        serviceRoles.forEach(role => roles.add(role))
      }
    }

    return roles
  }

  private resolvePermissions(
    roles: Set<string>,
    serviceRolesDef: FlatRolesMap | null,
    globalRolesDef: FlatRolesMap | null
  ): Set<string> {
    const permissions = new Set<string>()

    for (const roleName of roles) {
      if (globalRolesDef) {
        const perms = globalRolesDef[roleName]
        if (perms && Array.isArray(perms)) perms.forEach(p => permissions.add(p))
      }
      if (serviceRolesDef) {
        const perms = serviceRolesDef[roleName]
        if (perms && Array.isArray(perms)) perms.forEach(p => permissions.add(p))
      }
    }

    return permissions
  }
}

export const rbacResolverService = new RbacResolverService()
