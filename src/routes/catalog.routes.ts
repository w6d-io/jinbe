import type { FastifyInstance } from 'fastify'
import { ALIASES, CATALOG, PERMISSIONS } from '../policy/catalog.js'
import { ROLES, STAFF_ROLES } from '../policy/roles.js'
import { declaredRoutes } from '../policy/declared-routes.js'
import { open } from '../policy/route-access.js'
import { oauthGrantWindowHours, stepUpPermissionsOf, stepUpRule } from '../second-factor/requirements.js'
import { stepUpRuleJsonSchema } from '../schemas/second-factor.schema.js'

/**
 * GET /api/catalog — the permission catalogue, the staff roles and the legacy aliases, for kuma (nav
 * and button gates, proactive step-up) and auth-mcp (the scope list, what a key may never do).
 *
 * The same for every signed-in person: it says what exists, not what the caller holds (that is
 * `effective_permissions` on /api/whoami). Each permission lists the routes that require it, read off
 * the running route table, so a client never keeps its own copy of the mapping.
 */
export async function catalogRoutes(fastify: FastifyInstance) {
  fastify.get('/catalog', {
    ...open('authenticated'),
    schema: {
      description: 'The permission catalogue (labels, sensitivity, step-up and its rule, four-eyes, delegable, routes), the staff roles and the legacy aliases.',
      tags: ['auth'],
      response: {
        200: {
          type: 'object',
          properties: {
            permissions: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  area: { type: 'string' },
                  label: { type: 'string' },
                  sensitivity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
                  stepUp: { type: 'boolean' },
                  fourEyes: { type: ['string', 'boolean'] },
                  delegable: { type: 'string', enum: ['direct', 'never'] },
                  stepUpRule: stepUpRuleJsonSchema,
                  routes: {
                    type: 'array',
                    items: { type: 'object', properties: { method: { type: 'string' }, path: { type: 'string' } } },
                  },
                },
              },
            },
            roles: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  group: { type: 'string' },
                  label: { type: 'string' },
                  permissions: { type: 'array', items: { type: 'string' } },
                  stepUpPermissions: { type: 'array', items: { type: 'string' }, description: 'Its permissions that need a recent second factor' },
                },
              },
            },
            aliases: { type: 'object', additionalProperties: { type: 'array', items: { type: 'string' } } },
          },
        },
      },
    },
  }, async (_request, reply) => {
    const routes = new Map<string, { method: string; path: string }[]>()
    for (const r of declaredRoutes()) {
      if (!r.permission || r.method === 'HEAD') continue
      routes.set(r.permission, [...(routes.get(r.permission) ?? []), { method: r.method, path: r.path }])
    }
    const oauthHours = await oauthGrantWindowHours()
    return reply.send({
      permissions: PERMISSIONS.map((name) => ({ name, ...CATALOG[name], stepUpRule: stepUpRule(name, oauthHours), routes: routes.get(name) ?? [] })),
      roles: STAFF_ROLES.map((name) => ({ name, ...ROLES[name], permissions: [...ROLES[name].permissions], stepUpPermissions: stepUpPermissionsOf(ROLES[name].permissions) })),
      aliases: ALIASES,
    })
  })
}
