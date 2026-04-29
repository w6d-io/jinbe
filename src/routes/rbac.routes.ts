import type { FastifyInstance } from 'fastify'
import { env } from '../config/index.js'
import { rbacController } from '../controllers/rbac.controller.js'
import { requireAdmin } from '../middleware/require-admin.js'
import {
  unauthorizedResponseSchema,
  notFoundResponseSchema,
  forbiddenResponseSchema,
  badRequestResponseSchema,
  conflictResponseSchema,
} from '../schemas/response-schemas.js'
import {
  createGroupBodyJsonSchema,
  updateGroupBodyJsonSchema,
  groupJsonSchema,
  oathkeeperRuleJsonSchema,
} from '../schemas/rbac/index.js'

// =============================================================================
// RBAC Routes — Redis-backed, no branch prefix
// =============================================================================

export async function rbacRoutes(fastify: FastifyInstance) {
  // All RBAC admin routes require admin group membership
  fastify.addHook('preHandler', requireAdmin)

  // ===========================================================================
  // Users
  // ===========================================================================

  fastify.get('/users', {
    schema: {
      description: 'List all users with their group assignments.',
      tags: ['rbac'],
      response: {
        200: { type: 'object', properties: { users: { type: 'array', items: { type: 'object', additionalProperties: true } } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, rbacController.getUsers.bind(rbacController))

  // ===========================================================================
  // Groups
  // ===========================================================================

  fastify.get('/groups', {
    schema: {
      description: 'List all group definitions.',
      tags: ['rbac'],
      response: {
        200: { type: 'object', properties: { groups: { type: 'array', items: groupJsonSchema } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, rbacController.getGroups.bind(rbacController))

  fastify.post('/groups', {
    schema: {
      description: 'Create a new group.',
      tags: ['rbac'],
      body: createGroupBodyJsonSchema,
      response: {
        201: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        409: conflictResponseSchema,
      },
    },
  }, rbacController.createGroup.bind(rbacController))

  fastify.put('/groups/:name', {
    schema: {
      description: 'Update an existing group.',
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
      body: updateGroupBodyJsonSchema,
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.updateGroup.bind(rbacController))

  fastify.delete('/groups/:name', {
    schema: {
      description: 'Delete a group.',
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.deleteGroup.bind(rbacController))

  // ===========================================================================
  // Services
  // ===========================================================================

  fastify.get('/services', {
    schema: {
      description: 'List all configured services.',
      tags: ['rbac'],
      response: {
        200: { type: 'object', properties: { services: { type: 'array', items: { type: 'object', additionalProperties: true } } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, rbacController.getServices.bind(rbacController))

  fastify.post('/services', {
    schema: {
      description: 'Create a new service with default roles, route map, and oathkeeper rules.',
      tags: ['rbac'],
      body: {
        type: 'object', required: ['name'],
        properties: {
          name: { type: 'string', pattern: '^[a-z0-9_]+$' },
          displayName: { type: 'string' },
          upstreamUrl: { type: 'string', format: 'uri' },
          matchUrl: { type: 'string' },
          matchMethods: { type: 'array', items: { type: 'string' } },
          stripPath: { type: 'string' },
        },
      },
      response: {
        201: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        409: conflictResponseSchema,
      },
    },
  }, rbacController.createService.bind(rbacController))

  fastify.delete('/services/:name', {
    schema: {
      description: 'Delete a service and all associated roles, routes, and rules.',
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.deleteService.bind(rbacController))

  fastify.patch('/services/:name', {
    schema: {
      description: 'Update oathkeeper rule config for a service (upstream URL, match URL/methods, strip_path).',
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
      body: {
        type: 'object',
        properties: {
          upstreamUrl: { type: 'string', format: 'uri' },
          matchUrl: { type: 'string' },
          matchMethods: { type: 'array', items: { type: 'string' } },
          stripPath: { type: ['string', 'null'] },
        },
      },
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.updateServiceConfig.bind(rbacController))

  fastify.get('/services/:name/permissions', {
    schema: {
      description: 'List all unique permissions for a service (from roles + routes).',
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
      response: {
        200: { type: 'object', properties: { service: { type: 'string' }, permissions: { type: 'array', items: { type: 'string' } } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.getServicePermissions.bind(rbacController))

  fastify.get('/services/:name/roles', {
    schema: {
      description: 'Get roles for a specific service.',
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
      response: {
        200: { type: 'object', properties: { service: { type: 'string' }, roles: { type: 'array' } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.getServiceRoles.bind(rbacController))

  fastify.put('/services/:name/roles', {
    schema: {
      description: 'Replace roles for a specific service.',
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
      body: {
        type: 'object',
        required: ['roles'],
        properties: {
          roles: { type: 'object', additionalProperties: { type: 'array', items: { type: 'string' } } },
        },
      },
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.updateServiceRoles.bind(rbacController))

  fastify.get('/services/:name/routes', {
    schema: {
      description: 'Get route map for a specific service.',
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
      response: {
        200: { type: 'object', properties: { service: { type: 'string' }, rules: { type: 'array' } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.getServiceRoutes.bind(rbacController))

  fastify.put('/services/:name/routes', {
    schema: {
      description: 'Replace the route map for a specific service.',
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
      body: {
        type: 'object',
        required: ['rules'],
        properties: {
          rules: {
            type: 'array',
            items: {
              type: 'object',
              required: ['method', 'path'],
              properties: {
                method: { type: 'string' },
                path: { type: 'string' },
                permission: { type: 'string' },
              },
            },
          },
        },
      },
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.updateServiceRoutes.bind(rbacController))

  // ===========================================================================
  // Access Rules (Oathkeeper)
  // ===========================================================================

  fastify.get('/access-rules', {
    schema: {
      description: 'List all Oathkeeper access rules.',
      tags: ['rbac'],
      response: {
        200: { type: 'object', properties: { rules: { type: 'array', items: oathkeeperRuleJsonSchema } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, rbacController.getAccessRules.bind(rbacController))

  fastify.get('/access-rules/:id', {
    schema: {
      description: 'Get a specific access rule.',
      tags: ['rbac'],
      params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
      response: {
        200: { type: 'object', properties: { rule: oathkeeperRuleJsonSchema } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.getAccessRule.bind(rbacController))

  fastify.post('/access-rules', {
    schema: {
      description: 'Create a new access rule.',
      tags: ['rbac'],
      body: oathkeeperRuleJsonSchema,
      response: {
        201: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        409: conflictResponseSchema,
      },
    },
  }, rbacController.createAccessRule.bind(rbacController))

  fastify.put('/access-rules/:id', {
    schema: {
      description: 'Update an existing access rule.',
      tags: ['rbac'],
      params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
      body: oathkeeperRuleJsonSchema,
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.updateAccessRule.bind(rbacController))

  fastify.delete('/access-rules/:id', {
    schema: {
      description: 'Delete an access rule.',
      tags: ['rbac'],
      params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.deleteAccessRule.bind(rbacController))

  // ===========================================================================
  // Permission Simulator
  // ===========================================================================

  fastify.post('/simulate', {
    schema: {
      description: 'Simulate an authorization decision for a user, service, method, and path.',
      tags: ['rbac'],
      body: {
        type: 'object',
        required: ['email', 'service', 'method', 'path'],
        properties: {
          email: { type: 'string', format: 'email' },
          service: { type: 'string', minLength: 1 },
          method: { type: 'string', minLength: 1 },
          path: { type: 'string', minLength: 1 },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            allowed: { type: 'boolean' },
            matchedRule: {
              type: 'object',
              properties: {
                method: { type: 'string' },
                path: { type: 'string' },
                permission: { type: 'string' },
              },
            },
            requiredPermission: { type: 'string' },
            userInfo: {
              type: 'object',
              properties: {
                email: { type: 'string' },
                groups: { type: 'array', items: { type: 'string' } },
                roles: { type: 'array', items: { type: 'string' } },
                permissions: { type: 'array', items: { type: 'string' } },
              },
            },
          },
        },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, rbacController.simulate.bind(rbacController))

  fastify.post('/health-check', async (_request, reply) => {
    return reply.send({ status: 'ok', redis: true, opa: true })
  })

  fastify.get('/history', async (request, reply) => {
    // Proxy to the rich audit stream — returns FrontendAuditEvent[] as "commits" for backward compat
    try {
      const { auditEventService } = await import('../services/audit-event.service.js')
      const q = request.query as Record<string, string>
      const perPage = parseInt(q.perPage || '50', 10)
      const events = await auditEventService.query({ limit: perPage, category: q.category as never })
      // Map to legacy commit shape so existing callers don't break
      const commits = events.map(e => ({
        id:           e.id,
        message:      `${e.verb} ${e.target}`,
        authorEmail:  e.who,
        timestamp:    e.ts,
        filesChanged: [],
        // Rich fields (bonus)
        category: e.category, verb: e.verb, target: e.target, result: e.result,
        ip: e.ip, ua: e.ua, reason: e.reason,
      }))
      return reply.send({ commits, total: commits.length })
    } catch {
      return reply.send({ commits: [], total: 0 })
    }
  })
}

// =============================================================================
// OPAL Public Data Routes — no auth, called by OPAL server to sync policy data
// =============================================================================

import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { kratosService } from '../services/kratos.service.js'

export async function rbacOpalRoutes(fastify: FastifyInstance) {
  // Bindings: user → groups (from Kratos)
  fastify.get('/bindings', async (_request, reply) => {
    try {
      const identitiesWithGroups = await kratosService.getAllIdentitiesWithGroups()
      const group_membership: Record<string, string[]> = {}
      for (const [email, groups] of identitiesWithGroups) {
        group_membership[email] = groups
      }
      return reply.send({ emails: {}, group_membership })
    } catch {
      return reply.send({ emails: {}, group_membership: {} })
    }
  })

  // Groups: group → service → roles
  fastify.get('/opal/groups', async (_request, reply) => {
    const groups = await redisRbacRepository.getGroups()
    return reply.send(groups)
  })

  // Roles per service
  fastify.get('/opal/roles/:service', async (request, reply) => {
    const { service } = request.params as { service: string }
    const roles = await redisRbacRepository.getRoles(service)
    return reply.send(roles || {})
  })

  // Route map per service
  fastify.get('/opal/route_map/:service', async (request, reply) => {
    const { service } = request.params as { service: string }
    const routeMap = await redisRbacRepository.getRouteMap(service)
    return reply.send(routeMap || { rules: [] })
  })

  // OPAL datasource config (tells OPAL what to fetch)
  fastify.get('/opal-datasource', async (_request, reply) => {
    const services = await redisRbacRepository.getServices()
    const jinbeUrl = env.JINBE_INTERNAL_URL || 'http://jinbe:8080'

    const entries = [
      { url: `${jinbeUrl}/api/admin/rbac/bindings`, topics: ['policy_data'], dst_path: '/bindings' },
      { url: `${jinbeUrl}/api/admin/rbac/opal/groups`, topics: ['policy_data'], dst_path: '/bindings/groups' },
    ]

    for (const svc of services) {
      entries.push({ url: `${jinbeUrl}/api/admin/rbac/opal/roles/${svc}`, topics: ['policy_data'], dst_path: `/roles/${svc}` })
      const routeMap = await redisRbacRepository.getRouteMap(svc)
      if (routeMap) {
        entries.push({ url: `${jinbeUrl}/api/admin/rbac/opal/route_map/${svc}`, topics: ['policy_data'], dst_path: `/route_map/${svc}` })
      }
    }

    return reply.send({ entries })
  })
}
