import type { FastifyRequest, FastifyReply } from 'fastify'
import { rbacService } from '../services/rbac.service.js'
import { faviconService } from '../services/favicon.service.js'
import { getEnabledHandlers } from '../services/oathkeeper-handlers.js'
import {
  createGroupBodySchema,
  updateGroupBodySchema,
  type CreateGroupBody,
  type UpdateGroupBody,
} from '../schemas/rbac/index.js'
import { auditActor } from '../utils/audit-actor.js'
import { z } from 'zod'

// =============================================================================
// Controller — Redis-backed RBAC management
// =============================================================================

export class RbacController {
  // ===========================================================================
  // Helper
  // ===========================================================================

  // Shared audit-actor (A4/P2-5): email/name/ip/ua/sessionId + requestId.
  private actor(request: FastifyRequest) {
    return auditActor(request)
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

  async getServicePermissions(
    request: FastifyRequest<{ Params: { name: string } }>,
    reply: FastifyReply
  ) {
    const { name } = z.object({ name: z.string().min(1) }).parse(request.params)
    const result = await rbacService.getServicePermissions(name)
    return reply.send(result)
  }

  /**
   * Serve a service's cached favicon (fetched server-side by jinbe from the
   * service's own public host). Returns the image with its content-type and a
   * public Cache-Control, or 204 No Content when there's no favicon so kuma can
   * cleanly fall back to its default avatar. The :name param is guarded to the
   * service-name charset.
   */
  async getServiceFavicon(
    request: FastifyRequest<{ Params: { name: string } }>,
    reply: FastifyReply
  ) {
    const { name } = z
      .object({ name: z.string().min(1).regex(/^[a-z0-9_-]+$/) })
      .parse(request.params)
    const favicon = await faviconService.getFavicon(name)
    if (!favicon) {
      return reply.status(204).send()
    }
    return reply
      .header('Content-Type', favicon.contentType)
      .header('Cache-Control', `public, max-age=${7 * 24 * 60 * 60}`)
      .send(favicon.data)
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

  // ===========================================================================
  // Oathkeeper Handler Catalog
  // ===========================================================================

  /**
   * Return the Oathkeeper handlers ENABLED in the running gateway, grouped by
   * pipeline stage and carrying guided field descriptors. Feeds the admin UI's
   * handler pickers/forms so it can only ever offer handlers that will load.
   */
  async getOathkeeperHandlers(_request: FastifyRequest, reply: FastifyReply) {
    return reply.send(getEnabledHandlers())
  }

  // ===========================================================================
  // Org → Service Map
  // ===========================================================================

  async getOrgServiceMap(_request: FastifyRequest, reply: FastifyReply) {
    const mappings = await rbacService.getOrgServiceMap()
    return reply.send({ mappings })
  }

  async setOrgServiceMapping(
    request: FastifyRequest<{ Body: { organizationId: string; services: string[] } }>,
    reply: FastifyReply,
  ) {
    // Set-bundle semantics: the request replaces the org's ENTIRE service
    // bundle with `services`. Require at least one service — clearing the
    // mapping is DELETE /org-service-map/:organizationId.
    const body = z.object({
      organizationId: z.string().uuid(),
      services: z.array(z.string().min(1).regex(/^[a-z0-9_]+$/)).min(1),
    }).parse(request.body)
    await rbacService.setOrgServiceMapping(body.organizationId, body.services, this.actor(request))
    return reply.status(201).send({ success: true, message: `Mapped ${body.organizationId} → [${body.services.join(', ')}]` })
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
  // Org → Admin Roster (per-org admin list; feeds data.org_admin_map)
  // ===========================================================================

  async getOrgAdminMap(_request: FastifyRequest, reply: FastifyReply) {
    const mappings = await rbacService.getOrgAdminMap()
    return reply.send({ mappings })
  }

  async setOrgAdmins(request: FastifyRequest, reply: FastifyReply) {
    // Set-roster semantics: replaces the org's ENTIRE admin roster with `admins`
    // (emails). An empty list clears the roster (the org then has no delegated
    // admins). Gated at the route by super_admin + a recent second factor.
    const body = z.object({
      organizationId: z.string().uuid(),
      admins: z.array(z.string().email()).max(100),
    }).parse(request.body)
    await rbacService.setOrgAdmins(body.organizationId, body.admins, this.actor(request))
    return reply.status(200).send({
      success: true,
      message: `Roster for ${body.organizationId} set to [${body.admins.join(', ') || 'none'}]`,
    })
  }

  // Impact preview and the decision simulator lived here. Both asked an engine for `data.rbac.*`,
  // a path that stopped existing when the model became `strada.authz` — they answered nothing, so
  // the screens over them showed an error whatever was asked.
  //
  // Replaying a real decision is worth having back: it answers "would this person be allowed to
  // call that" — the verdict, not the chain. It needs an engine this service can reach, and the one that enforces listens on the
  // loopback of the proxy pod. A preview engine of its own, off the request path, is the shape.
  //
  // The hypothetical half is not: `impact-preview` asked "what changes if I edit the model", and
  // the artefact's roots are read-only, so it would need either a parameterised policy — which
  // means an override inside the policy that enforces — or a second evaluation of a world that
  // exists nowhere. Not worth its price.
}

export const rbacController = new RbacController()
