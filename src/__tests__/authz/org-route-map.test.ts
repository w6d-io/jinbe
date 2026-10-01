import { describe, it, expect, vi } from 'vitest'
import Fastify from 'fastify'

// The org guards ask OPA's `rbac.decision` about the request itself, so every route they guard must
// be a row of the jinbe route_map — a route missing there is `not_found`, refused for everybody.

vi.mock('../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { organizationUserRoutes } from '../../routes/organization-user.routes.js'
import { apiKeyRoutes } from '../../routes/api-key.routes.js'
import { orgRolesRoutes } from '../../routes/org-roles.routes.js'
import { GENERATED_ROUTE_MAP } from '../../policy/route-map.generated.js'

async function routesOf(plugin: (f: never) => Promise<void>): Promise<Array<[string, string]>> {
  const seen: Array<[string, string]> = []
  const app = Fastify()
  app.addHook('onRoute', (r) => {
    for (const m of [r.method].flat()) if (m !== 'HEAD') seen.push([m, r.url])
  })
  await app.register(plugin as never, { prefix: '/api/organizations/:organizationId' })
  await app.ready()
  await app.close()
  return seen
}

describe('every OPA-decided org route is an org row (org_param) of the jinbe route_map', () => {
  for (const [name, plugin] of [
    ['organization-user', organizationUserRoutes],
    ['api-keys', apiKeyRoutes],
    ['org-roles', orgRolesRoutes],
  ] as const) {
    it(name, async () => {
      const rows = new Set(GENERATED_ROUTE_MAP.filter((r) => r.org_param).map((r) => `${r.method} ${r.path}`))
      const routes = await routesOf(plugin as never)
      expect(routes.length).toBeGreaterThan(0)
      expect(routes.map(([m, p]) => `${m} ${p}`).filter((k) => !rows.has(k))).toEqual([])
    })
  }
})
