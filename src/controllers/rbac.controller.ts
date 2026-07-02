import type { FastifyRequest, FastifyReply } from 'fastify'
import { rbacService } from '../services/rbac.service.js'
import { opaService } from '../services/opa.service.js'
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
    request: FastifyRequest<{ Body: { name: string; displayName?: string; upstreamUrl?: string; matchUrl?: string; matchMethods?: string[]; stripPath?: string } }>,
    reply: FastifyReply
  ) {
    const options = z
      .object({
        name: z.string().min(1).regex(/^[a-z0-9_]+$/, 'Service name must be lowercase alphanumeric with underscores'),
        displayName: z.string().optional(),
        upstreamUrl: z.string().url().optional(),
        matchUrl: z.string().optional(),
        matchMethods: z.array(z.string()).optional(),
        stripPath: z.string().optional(),
      })
      .parse(request.body)

    const result = await rbacService.createService(options, this.actor(request))
    return reply.status(201).send(result)
  }

  async updateServiceConfig(
    request: FastifyRequest<{ Params: { name: string }; Body: { upstreamUrl?: string; matchUrl?: string; matchMethods?: string[]; stripPath?: string | null } }>,
    reply: FastifyReply
  ) {
    const { name } = z.object({ name: z.string().min(1) }).parse(request.params)
    const options = z.object({
      upstreamUrl: z.string().url().optional(),
      matchUrl: z.string().optional(),
      matchMethods: z.array(z.string()).optional(),
      stripPath: z.string().nullable().optional(),
    }).parse(request.body)
    const result = await rbacService.updateServiceConfig(name, options, this.actor(request))
    return reply.send(result)
  }

  async getServicePermissions(
    request: FastifyRequest<{ Params: { name: string } }>,
    reply: FastifyReply
  ) {
    const { name } = z.object({ name: z.string().min(1) }).parse(request.params)
    const result = await rbacService.getServicePermissions(name)
    return reply.send(result)
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
  // Org → Service Map
  // ===========================================================================

  async getOrgServiceMap(_request: FastifyRequest, reply: FastifyReply) {
    const mappings = await rbacService.getOrgServiceMap()
    return reply.send({ mappings })
  }

  async setOrgServiceMapping(
    request: FastifyRequest<{ Body: { organizationId: string; serviceName: string } }>,
    reply: FastifyReply,
  ) {
    const body = z.object({
      organizationId: z.string().uuid(),
      serviceName: z.string().min(1).regex(/^[a-z0-9_]+$/),
    }).parse(request.body)
    await rbacService.setOrgServiceMapping(body.organizationId, body.serviceName, this.actor(request))
    return reply.status(201).send({ success: true, message: `Mapped ${body.organizationId} → ${body.serviceName}` })
  }

  async deleteOrgServiceMapping(
    request: FastifyRequest<{ Params: { organizationId: string } }>,
    reply: FastifyReply,
  ) {
    const { organizationId } = z.object({ organizationId: z.string().uuid() }).parse(request.params)
    await rbacService.deleteOrgServiceMapping(organizationId, this.actor(request))
    return reply.send({ success: true, message: `Mapping removed for ${organizationId}` })
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

    // Single round-trip to OPA — same code path as oathkeeper request-time
    // authorization, so the simulator can never drift from production decisions.
    const result = await opaService.simulate(
      body.email,
      body.service,
      body.method.toUpperCase(),
      body.path,
    )

    if (!result) {
      return reply.code(503).send({
        error: 'opa_unreachable',
        message: 'Could not query OPA for live decision',
      })
    }

    const matchedRule = result.matching_rules[0]
    const requiredPermission = matchedRule?.permission

    return reply.send({
      allowed: result.allow,
      matchedRule: matchedRule ?? undefined,
      requiredPermission,
      superAdmin: result.super_admin,
      userInfo: {
        email: body.email,
        groups: result.groups,
        roles: result.roles,
        permissions: result.permissions,
      },
    })
  }
}

export const rbacController = new RbacController()
