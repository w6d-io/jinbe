import type { FastifyInstance } from 'fastify'
import { rbacController } from '../controllers/rbac.controller.js'
import { requireAdmin, requireSuperAdmin, requireRecentMfa } from '../middleware/require-admin.js'
import { refuseWhenSourcedFromGit } from '../middleware/refuse-when-sourced-from-git.js'
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
  oathkeeperRuleJsonSchema,
} from '../schemas/rbac/index.js'

// Response schema for GET /oathkeeper/handlers. A handler descriptor is the
// plain-language shape the admin UI renders (label/description + guided fields);
// an explicit schema keeps fast-json-stringify from stripping nested fields.
const handlerDescriptorJsonSchema = {
  type: 'object',
  properties: {
    handler: { type: 'string' },
    label: { type: 'string' },
    description: { type: 'string' },
    hasFreeformConfig: { type: 'boolean' },
    fields: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          key: { type: 'string' },
          label: { type: 'string' },
          type: {
            type: 'string',
            enum: ['string', 'url', 'bool', 'textarea', 'kv', 'list', 'json'],
          },
          required: { type: 'boolean' },
          placeholder: { type: 'string' },
          help: { type: 'string' },
        },
        required: ['key', 'label', 'type'],
      },
    },
  },
  required: ['handler', 'label', 'description', 'hasFreeformConfig', 'fields'],
}

const oathkeeperHandlerCatalogJsonSchema = {
  type: 'object',
  properties: {
    authenticators: { type: 'array', items: handlerDescriptorJsonSchema },
    authorizers: { type: 'array', items: handlerDescriptorJsonSchema },
    mutators: { type: 'array', items: handlerDescriptorJsonSchema },
    errorHandlers: { type: 'array', items: handlerDescriptorJsonSchema },
  },
  required: ['authenticators', 'authorizers', 'mutators', 'errorHandlers'],
}

// =============================================================================
// RBAC Routes — Redis-backed, no branch prefix
// =============================================================================

export async function rbacRoutes(fastify: FastifyInstance) {
  // All RBAC admin routes require admin group membership
  fastify.addHook('preHandler', requireAdmin)

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
    preHandler: refuseWhenSourcedFromGit,
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
  }, rbacController.updateServiceRoutes.bind(rbacController) as never)

  fastify.post('/services/:name/routes/import/preview', {
    preHandler: refuseWhenSourcedFromGit,
    bodyLimit: 8 * 1024 * 1024, // OpenAPI specs can be large
    schema: {
      description:
        'Dry-run: parse an OpenAPI/Swagger spec and preview the route rules + diff it would produce for a service. Does not mutate; apply is PUT /services/:name/routes.',
      tags: ['rbac'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } },
      body: {
        type: 'object',
        required: ['source'],
        properties: {
          source: {
            type: 'object',
            properties: {
              url: { type: 'string' },
              content: { type: 'string' },
              format: { type: 'string', enum: ['json', 'yaml', 'auto'] },
            },
          },
          options: {
            type: 'object',
            properties: {
              resourceFrom: { type: 'string', enum: ['tag', 'path', 'operationId'] },
              verbMap: { type: 'object', additionalProperties: { type: 'string' } },
              listAsRead: { type: 'boolean' },
              honorExtension: { type: 'boolean' },
              scopeMap: { type: 'object', additionalProperties: { type: 'string' } },
              basePath: { type: 'string', enum: ['prepend', 'strip', 'none'] },
            },
          },
        },
      },
      // No 200 response schema: the preview payload is rich/nested — let Fastify
      // serialize it as-is rather than risk fast-json-stringify stripping fields.
      response: {
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, rbacController.importRoutesPreview.bind(rbacController) as never)

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

  fastify.get('/oathkeeper/handlers', {
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
  }, rbacController.setOrgServiceMapping.bind(rbacController))

  // Org → admin roster (per-org admin list; feeds data.org_admin_map).
  fastify.get('/org-admin-map', {
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
    preHandler: [requireSuperAdmin, requireRecentMfa],
    schema: {
      description: "Set an organization's admin roster (emails). Replaces the org's entire roster; an empty list clears it. Requires super_admin + a second factor proven within 15 minutes.",
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
  }, rbacController.deleteOrgServiceMapping.bind(rbacController))

  // ===========================================================================
  // Impact preview — "who gains/loses access if this change is applied?"
  // ===========================================================================

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

import { rbacService } from '../services/rbac.service.js'

export async function rbacOpalRoutes(fastify: FastifyInstance) {
  // Bindings: user → groups + org membership (from Kratos). Routed through the
  // service so the shape can't drift from the tested getBindingsFromKratos().
  fastify.get('/bindings', async (_request, reply) => {
    try {
      const bindings = await rbacService.getBindingsFromKratos()
      return reply.send(bindings)
    } catch {
      // Fail closed: if Kratos is unreachable, publish an empty (full-shape)
      // dataset so OPA denies rather than authorizing against stale/partial data.
      return reply.send({
        emails: {},
        group_membership: {},
        user_organizations: {},
        user_organization_primary: {},
      })
    }
  })

  // Groups: group → service → roles
  // Six routes lived here whose only caller was OPAL: the datasource manifest and the five
  // documents it fetched. No OPAL runs in this namespace, and the engine pulls a bundle rather
  // than being pushed data — so they answered nobody, and the push that used to name them logged
  // a DNS error on every mutation for a component that never existed here.

}
