/**
 * Regenerate src/policy/route-map.generated.ts — jinbe's route_map rows — from the routes the server
 * declares (policy/route-map.ts). CI (route-map.test.ts) fails when the committed file is stale.
 *
 * Builds the server without listening, like generate-openapi.ts; nothing external is contacted.
 */
import { writeFile } from 'fs/promises'
import { buildServer } from '../server.js'
import { declaredRoutes } from '../policy/declared-routes.js'
import { renderRouteMapModule, routeMapRows } from '../policy/route-map.js'

async function main() {
  const fastify = await buildServer()
  await fastify.ready()
  const rows = routeMapRows(declaredRoutes())
  await writeFile(new URL('../policy/route-map.generated.ts', import.meta.url), renderRouteMapModule(rows), 'utf8')
  await fastify.close()
  // eslint-disable-next-line no-console
  console.log(`route-map.generated.ts regenerated: ${rows.length} rows`)
  process.exit(0)
}

main().catch((err) => {
  console.error('route map generation failed:', err)
  process.exit(1)
})
