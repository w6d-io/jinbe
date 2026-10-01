/**
 * Regenerate src/policy/route-map.generated.ts (v1) and src/authz-v2/route-map.generated.ts (v2) — jinbe's route_map rows — from the routes the server
 * declares (policy/route-map.ts). CI (route-map.test.ts) fails when the committed file is stale.
 *
 * Builds the server without listening, like generate-openapi.ts; nothing external is contacted.
 */
import { writeFile } from 'fs/promises'
import { buildServer } from '../server.js'
import { declaredRoutes } from '../policy/declared-routes.js'
import { renderRouteMapModule, routeMapRows } from '../policy/route-map.js'
import { renderRouteRowsV2Module, routeRowsV2 } from '../authz-v2/route-rows.js'

async function main() {
  const fastify = await buildServer()
  await fastify.ready()
  const rows = routeMapRows(declaredRoutes())
  await writeFile(new URL('../policy/route-map.generated.ts', import.meta.url), renderRouteMapModule(rows), 'utf8')
  const v2 = routeRowsV2(declaredRoutes())
  await writeFile(new URL('../authz-v2/route-map.generated.ts', import.meta.url), renderRouteRowsV2Module(v2), 'utf8')
  await fastify.close()
  // eslint-disable-next-line no-console
  console.log(`route-map.generated.ts regenerated: ${rows.length} rows (v2: ${v2.length})`)
  process.exit(0)
}

main().catch((err) => {
  console.error('route map generation failed:', err)
  process.exit(1)
})
