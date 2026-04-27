import type { FastifyRequest, FastifyReply } from 'fastify'
import { rbacService } from '../services/rbac.service.js'
import { rbacResolverService } from '../services/rbac-resolver.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import {
  createGroupBodySchema,
  updateGroupBodySchema,
  oathkeeperRuleSchema,
  type CreateGroupBody,
  type UpdateGroupBody,
  type OathkeeperRule,
} from '../schemas/rbac/index.js'
import { z } from 'zod'

// =============================================================================
// Controller — Redis-backed RBAC management
// =============================================================================

export class RbacController {
  // ===========================================================================
  // Helper
  // ===========================================================================

  private actor(request: FastifyRequest) {
    return { email: request.userContext?.email, ip: request.ip }
  }

  // ===========================================================================
  // Users
  // ===========================================================================

  async getUsers(_request: FastifyRequest, reply: FastifyReply) {
    const result = await rbacService.getUsers()
    return reply.send(result)
  }

  // ===========================================================================
  // Groups
  // ===========================================================================

  async getGroups(_request: FastifyRequest, reply: FastifyReply) {
    const result = await rbacService.getGroups()
    return reply.send(result)
  }

  async createGroup(
    request: FastifyRequest<{ Body: CreateGroupBody }>,
    reply: FastifyReply
  ) {
    const { name, services } = createGroupBodySchema.parse(request.body)
    const result = await rbacService.createGroup(name, services, this.actor(request))
    return reply.status(201).send(result)
  }

  async updateGroup(
    request: FastifyRequest<{ Params: { name: string }; Body: UpdateGroupBody }>,
    reply: FastifyReply
  ) {
    const { name } = z.object({ name: z.string().min(1) }).parse(request.params)
    const { services } = updateGroupBodySchema.parse(request.body)
    const result = await rbacService.updateGroup(name, services, this.actor(request))
    return reply.send(result)
  }

  async deleteGroup(
    request: FastifyRequest<{ Params: { name: string } }>,
    reply: FastifyReply
  ) {
    const { name } = z.object({ name: z.string().min(1) }).parse(request.params)
    const result = await rbacService.deleteGroup(name, this.actor(request))
    return reply.send(result)
  }

  // ===========================================================================
  // Services
  // ===========================================================================

  async getServices(_request: FastifyRequest, reply: FastifyReply) {
    const result = await rbacService.getServices()
    return reply.send(result)
  }

  async createService(
    request: FastifyRequest<{ Body: { name: string; displayName?: string; upstreamUrl?: string; matchUrl?: string; matchMethods?: string[] } }>,
    reply: FastifyReply
  ) {
    const options = z
      .object({
        name: z.string().min(1).regex(/^[a-z0-9_]+$/, 'Service name must be lowercase alphanumeric with underscores'),
        displayName: z.string().optional(),
        upstreamUrl: z.string().url().optional(),
        matchUrl: z.string().optional(),
        matchMethods: z.array(z.string()).optional(),
      })
      .parse(request.body)

    const result = await rbacService.createService(options, this.actor(request))
    return reply.status(201).send(result)
  }

  async deleteService(
    request: FastifyRequest<{ Params: { name: string } }>,
    reply: FastifyReply
  ) {
    const { name } = z.object({ name: z.string().min(1) }).parse(request.params)
    const result = await rbacService.deleteService(name, this.actor(request))
    return reply.send(result)
  }

  async getServiceRoles(
    request: FastifyRequest<{ Params: { name: string } }>,
    reply: FastifyReply
  ) {
    const { name } = z.object({ name: z.string().min(1) }).parse(request.params)
    const result = await rbacService.getServiceRoles(name)
    return reply.send(result)
  }

  async getServiceRoutes(
    request: FastifyRequest<{ Params: { name: string } }>,
    reply: FastifyReply
  ) {
    const { name } = z.object({ name: z.string().min(1) }).parse(request.params)
    const result = await rbacService.getServiceRoutes(name)
    return reply.send(result)
  }

  async updateServiceRoles(
    request: FastifyRequest<{ Params: { name: string }; Body: { roles: Record<string, string[]> } }>,
    reply: FastifyReply
  ) {
    const { name } = z.object({ name: z.string().min(1) }).parse(request.params)
    const { roles } = z.object({ roles: z.record(z.array(z.string())) }).parse(request.body)
    const result = await rbacService.updateServiceRoles(name, roles, this.actor(request))
    return reply.send(result)
  }

  async updateServiceRoutes(
    request: FastifyRequest<{ Params: { name: string }; Body: { rules: Array<{ method: string; path: string; permission?: string }> } }>,
    reply: FastifyReply
  ) {
    const { name } = z.object({ name: z.string().min(1) }).parse(request.params)
    const { rules } = z.object({
      rules: z.array(z.object({
        method: z.string().min(1),
        path: z.string().min(1),
        permission: z.string().optional(),
      })),
    }).parse(request.body)
    const result = await rbacService.updateServiceRoutes(name, rules, this.actor(request))
    return reply.send(result)
  }

  // ===========================================================================
  // Access Rules (Oathkeeper)
  // ===========================================================================

  async getAccessRules(_request: FastifyRequest, reply: FastifyReply) {
    const result = await rbacService.getAccessRules()
    return reply.send(result)
  }

  async getAccessRule(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply
  ) {
    const { id } = z.object({ id: z.string().min(1) }).parse(request.params)
    const result = await rbacService.getAccessRule(id)
    return reply.send(result)
  }

  async createAccessRule(
    request: FastifyRequest<{ Body: OathkeeperRule }>,
    reply: FastifyReply
  ) {
    const rule = oathkeeperRuleSchema.parse(request.body)
    const result = await rbacService.createAccessRule(rule, this.actor(request))
    return reply.status(201).send(result)
  }

  async updateAccessRule(
    request: FastifyRequest<{ Params: { id: string }; Body: OathkeeperRule }>,
    reply: FastifyReply
  ) {
    const { id } = z.object({ id: z.string().min(1) }).parse(request.params)
    const rule = oathkeeperRuleSchema.parse(request.body)

    if (rule.id !== id) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: `Rule ID in body (${rule.id}) does not match URL parameter (${id})`,
      })
    }

    const result = await rbacService.updateAccessRule(id, rule, this.actor(request))
    return reply.send(result)
  }

  async deleteAccessRule(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply
  ) {
    const { id } = z.object({ id: z.string().min(1) }).parse(request.params)
    const result = await rbacService.deleteAccessRule(id, this.actor(request))
    return reply.send(result)
  }

  // ===========================================================================
  // Permission Simulator
  // ===========================================================================

  async simulate(
    request: FastifyRequest<{
      Body: { email: string; service: string; method: string; path: string }
    }>,
    reply: FastifyReply
  ) {
    const body = z
      .object({
        email: z.string().email(),
        service: z.string().min(1),
        method: z.string().min(1),
        path: z.string().min(1),
      })
      .parse(request.body)

    // 1. Resolve user RBAC
    const userRbac = await rbacResolverService.resolveUserRbac(body.email, body.service)

    // 2. Get route_map for the service
    const routeMap = await redisRbacRepository.getRouteMap(body.service)
    const rules = routeMap?.rules ?? []

    // 3. Find matching rule
    const matchedRule = rules.find((rule) =>
      matchesMethod(rule.method, body.method) && matchesPath(rule.path, body.path)
    )

    // 4. Determine authorization
    let allowed: boolean
    let requiredPermission: string | undefined

    if (!matchedRule) {
      // No matching rule — treated as public (no route_map entry)
      allowed = true
    } else if (!matchedRule.permission) {
      // Matching rule but no permission required — public endpoint
      allowed = true
    } else {
      // Permission required — check user has it (including wildcard *)
      requiredPermission = matchedRule.permission
      allowed =
        userRbac.permissions.includes('*') ||
        userRbac.permissions.includes(requiredPermission)
    }

    return reply.send({
      allowed,
      matchedRule: matchedRule ?? undefined,
      requiredPermission,
      userInfo: {
        email: userRbac.email,
        groups: userRbac.groups,
        roles: userRbac.roles,
        permissions: userRbac.permissions,
      },
    })
  }
}

// =============================================================================
// Path matching helpers (mirrors rbac.rego logic)
// =============================================================================

/**
 * Match HTTP method: exact match or wildcard '*'
 */
function matchesMethod(ruleMethod: string, requestMethod: string): boolean {
  if (ruleMethod === '*') return true
  return ruleMethod.toUpperCase() === requestMethod.toUpperCase()
}

/**
 * Match request path against a route_map pattern.
 *
 * Supports the same patterns as the Rego policy:
 *   - exact match:  /api/users
 *   - :param        matches a single segment  (/api/users/:id -> /api/users/123)
 *   - :any*         matches one or more trailing segments (/api/:any* -> /api/foo/bar)
 */
function matchesPath(pattern: string, requestPath: string): boolean {
  const patternParts = pattern.split('/').filter(Boolean)
  const requestParts = requestPath.split('/').filter(Boolean)

  for (let i = 0; i < patternParts.length; i++) {
    const pp = patternParts[i]

    // Glob-style trailing wildcard: matches rest of path
    if (pp.endsWith('*')) {
      // Everything from this segment onward is accepted as long as there is
      // at least one more segment in the request
      return requestParts.length >= i + 1
    }

    // Single-segment parameter placeholder
    if (pp.startsWith(':')) {
      if (i >= requestParts.length) return false
      continue // any single segment matches
    }

    // Exact segment match
    if (i >= requestParts.length || pp !== requestParts[i]) {
      return false
    }
  }

  // All pattern parts consumed — lengths must match (no wildcard)
  return patternParts.length === requestParts.length
}

export const rbacController = new RbacController()
