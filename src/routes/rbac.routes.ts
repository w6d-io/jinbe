import type { FastifyInstance } from 'fastify'
import { rbacController } from '../controllers/rbac.controller.js'
import { needs } from '../policy/route-access.js'
import { refuseWhenSourcedFromGit } from '../middleware/refuse-when-sourced-from-git.js'
import { accessCheckRoutes } from './access-check.routes.js'
import { SERVICE_NAME_PATTERN } from '../services/rbac.service.js'
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
} from '../schemas/rbac/index.js'
import { oathkeeperHandlerCatalogJsonSchema } from '../schemas/rbac/oathkeeper-handlers.schema.js'

// =============================================================================
// RBAC Routes — Redis-backed, no branch prefix
// =============================================================================

export async function rbacRoutes(fastify: FastifyInstance) {
  // Each route declares its catalogue permission; there is no plugin-wide gate.
  await fastify.register(accessCheckRoutes)

  // ===========================================================================
  // Users
  // ===========================================================================

  // The writes that used to live here are gone, and so are /simulate and /impact-preview.
  //
  // The access-rule writes propagated to the gateway at runtime; the rules come from Git now, so a
  // write here would be overwritten by the next reconcile at best. The service registry keyed
  // grants per service, which this model does not: it keys them per organisation. And both replay
  // screens asked an engine for `data.rbac.*`, a path that stopped existing when the model became
  // `strada.authz` — they answered nothing.
  //
  // Reads are untouched: what exists is still listed. Only the ways to change it through a retired
  // model are gone.

  fastify.get('/users', {
    ...needs('users:read'),
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
    ...needs('groups:read'),
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
    ...needs('groups:write'),
    // groups:write (step-up from the catalogue): this changes who holds what.
    preHandler: refuseWhenSourcedFromGit,
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
  }, rbacController.createGroup.bind(rbacController) as never)

  fastify.put('/groups/:name', {
    ...needs('groups:write'),
    // groups:write (step-up from the catalogue): this changes who holds what.
    preHandler: refuseWhenSourcedFromGit,
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
  }, rbacController.updateGroup.bind(rbacController) as never)

  fastify.delete('/groups/:name', {
    ...needs('groups:write'),
    // groups:write (step-up from the catalogue): this changes who holds what.
    preHandler: refuseWhenSourcedFromGit,
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
  }, rbacController.deleteGroup.bind(rbacController) as never)

  // ===========================================================================
  // Services
  // ===========================================================================

  fastify.get('/services', {
    ...needs('sites:read'),
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

  fastify.get('/services/:name/permissions', {
    ...needs('sites:read'),
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

  fastify.get('/services/:name/favicon', {
    ...needs('sites:read'),
    schema: {
      description:
        "Serve the service's favicon, fetched server-side by jinbe from the service's own public host and cached in Redis (7d). Returns the image with a public Cache-Control, or 204 No Content when there is no favicon.",
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string', pattern: SERVICE_NAME_PATTERN.source } } },
      // No 200/204 body schema: the payload is a raw image (binary) — let it
      // pass through unserialized. Error shapes are still enforced.
      response: {
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, rbacController.getServiceFavicon.bind(rbacController))

  fastify.get('/services/:name/roles', {
    ...needs('sites:read'),
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
    ...needs('groups:write'),
    // groups:write (step-up from the catalogue): this changes who holds what.
    preHandler: refuseWhenSourcedFromGit,
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
  }, rbacController.updateServiceRoles.bind(rbacController) as never)

  fastify.get('/services/:name/routes', {
    ...needs('sites:read'),
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
    ...needs('groups:write'),
    // groups:write (step-up from the catalogue): this changes who holds what.
    preHandler: refuseWhenSourcedFromGit,
    schema: {
      description: 'Replace the route map for a specific service. 409 when a route ties with another service\'s at the same specificity (exact == exact, same :param shape, same :any* prefix): the policy would leave it with no owner and refuse every request on it.',
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
                public: { type: 'boolean', description: 'Open to anyone; per-site 2FA never gates it.' },
                org_param: {
                  type: 'string',
                  description: 'Name of the :param in `path` carrying the org id; the route is then that org\'s only. 400 when the path has no such param.',
                },
              },
            },
          },
        },
      },
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, timestamp: { type: 'string' } } },
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
        409: conflictResponseSchema,
      },
    },
  }, rbacController.updateServiceRoutes.bind(rbacController) as never)

  // ===========================================================================
  // Oathkeeper handlers
  // ===========================================================================

  fastify.get('/oathkeeper/handlers', {
    ...needs('gateway:read'),
    schema: {
      description:
        'List the Oathkeeper handlers ENABLED in the running gateway, grouped by pipeline stage, each with guided field descriptors. Drives the admin UI handler pickers/forms so it only offers handlers the gateway will accept.',
      tags: ['rbac'],
      response: {
        200: oathkeeperHandlerCatalogJsonSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, rbacController.getOathkeeperHandlers.bind(rbacController))

  // ===========================================================================
  // Org → Service Map
  // ===========================================================================

  fastify.get('/org-service-map', {
    ...needs('org:read'),
    schema: {
      description: 'List all organization → service bundle mappings (each org maps to an array of service names).',
      tags: ['rbac'],
      response: {
        200: {
          type: 'object',
          properties: {
            mappings: {
              type: 'object',
              additionalProperties: { type: 'array', items: { type: 'string' } },
            },
          },
        },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, rbacController.getOrgServiceMap.bind(rbacController))

  fastify.put('/org-service-map', {
    ...needs('groups:write'),
    // groups:write (step-up from the catalogue): which services an org's members reach.
    schema: {
      description: 'Set an organization → service bundle mapping. Replaces the org\'s entire bundle with the provided (non-empty) list of service names.',
      tags: ['rbac'],
      body: {
        type: 'object',
        required: ['organizationId', 'services'],
        properties: {
          organizationId: { type: 'string', format: 'uuid' },
          services: {
            type: 'array',
            minItems: 1,
            items: { type: 'string', pattern: SERVICE_NAME_PATTERN.source },
          },
        },
      },
      response: {
        201: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' } } },
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, rbacController.setOrgServiceMapping.bind(rbacController) as never)

  // Org → admin roster (per-org admin list; feeds data.org_admin_map).
  fastify.get('/org-admin-map', {
    ...needs('org:read'),
    schema: {
      description: 'List all organization → admin roster mappings (each org maps to an array of admin emails).',
      tags: ['rbac'],
      response: {
        200: {
          type: 'object',
          properties: {
            mappings: { type: 'object', additionalProperties: { type: 'array', items: { type: 'string' } } },
          },
        },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, rbacController.getOrgAdminMap.bind(rbacController))

  // Set an org's admin roster. super_admin + a RECENT second factor (R2 step-up)
  // are required — assigning who administers an org is a privileged action.
  fastify.put('/org-admin-map', {
    ...needs('org.admins:write'),
    schema: {
      description: "Set an organization's admin roster (emails). Replaces the org's entire roster; an empty list clears it. Requires org.admins:write + a second factor proven within 15 minutes.",
      tags: ['rbac'],
      body: {
        type: 'object',
        required: ['organizationId', 'admins'],
        properties: {
          organizationId: { type: 'string', format: 'uuid' },
          admins: { type: 'array', items: { type: 'string', format: 'email' } },
        },
      },
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' } } },
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        422: { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } },
      },
    },
  }, rbacController.setOrgAdmins.bind(rbacController))

  fastify.delete('/org-service-map/:organizationId', {
    ...needs('groups:write'),
    // groups:write (step-up from the catalogue): which services an org's members reach.
    schema: {
      description: 'Delete an organization → service bundle mapping (clears the org\'s bundle).',
      tags: ['rbac'],
      params: { type: 'object', required: ['organizationId'], properties: { organizationId: { type: 'string', format: 'uuid' } } },
      response: {
        200: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' } } },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.deleteOrgServiceMapping.bind(rbacController) as never)

  // POST /health-check is gone: a constant {status:'ok'} behind admin:read, with no caller — a write
  // verb that asked only for reading, and a liveness answer that checked nothing.
}
