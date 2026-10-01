import type { FastifyInstance } from 'fastify'
import { CATALOG, PERMISSIONS } from '../policy/catalog.js'
import { EVERY_ORG, ORG_ROLE_NAMES, ORG_ROLES, ROLES, STAFF_ROLES, JINBE, qualified } from '../policy/roles.js'
import { declaredRoutes } from '../policy/declared-routes.js'
import { open } from '../policy/route-access.js'
import { oauthGrantWindowHours, stepUpPermissionsOf, stepUpRule } from '../second-factor/requirements.js'
import { stepUpRuleJsonSchema } from '../schemas/second-factor.schema.js'

/**
 * GET /api/catalog — the permission catalogue (each with its scope: platform or org), the staff roles
 * with what they carry into every org, and jinbe's org roles, for kuma (nav and button gates,
 * proactive step-up, the org roles screen) and auth-mcp (the scope list, what a key may never do).
 *
 * The same for every signed-in person: it says what exists, not what the caller holds (that is
 * `effective_permissions` on /api/whoami). Each permission lists the routes that require it, read off
 * the running route table, so a client never keeps its own copy of the mapping.
 */
export async function catalogRoutes(fastify: FastifyInstance) {
  fastify.get('/catalog', {
    ...open('authenticated'),
    schema: {
      description: 'The permission catalogue (scope, labels, sensitivity, step-up and its rule, four-eyes, delegable, routes), the staff roles (with their every-org permissions) and jinbe\'s org roles.',
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
                  scope: { type: 'string', enum: ['platform', 'org'] },
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
                  everyOrg: { type: 'array', items: { type: 'string' }, description: 'Org permissions it holds in every organisation' },
                  stepUpPermissions: { type: 'array', items: { type: 'string' }, description: 'Its permissions that need a recent second factor' },
                },
              },
            },
            orgRoles: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  name: { type: 'string', description: 'svc:role, as assigned in an organisation' },
                  label: { type: 'string' },
                  permissions: { type: 'array', items: { type: 'string' } },
                },
              },
            },
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
      roles: STAFF_ROLES.map((name) => ({
        name, ...ROLES[name], permissions: [...ROLES[name].permissions], everyOrg: [...(EVERY_ORG[name] ?? [])],
        stepUpPermissions: stepUpPermissionsOf(ROLES[name].permissions),
      })),
      orgRoles: ORG_ROLE_NAMES.map((name) => ({ name: qualified(JINBE, name), label: ORG_ROLES[name].label, permissions: [...ORG_ROLES[name].permissions] })),
    })
  })
}
