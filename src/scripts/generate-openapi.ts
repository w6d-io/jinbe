/**
 * Regenerate openapi.yaml from the live route schemas.
 *
 * Runs as part of `npm run build` so the committed spec can never drift from
 * the actual Fastify routes again (the previous openapi.yaml was a stale
 * hand-written file describing an older API).
 *
 * Builds the server (registers every route + @fastify/swagger), awaits ready,
 * serializes the generated document, and exits WITHOUT listening. External
 * dependencies (Redis/Mongo/Kratos) are not contacted at registration time.
 */
import { writeFile } from 'fs/promises'
import { stringify } from 'yaml'
import { buildServer } from '../server.js'

async function main() {
  const fastify = await buildServer()
  await fastify.ready()
  const spec = fastify.swagger()
  await writeFile(new URL('../../openapi.yaml', import.meta.url), stringify(spec), 'utf8')
  await fastify.close()
  // eslint-disable-next-line no-console
  console.log('openapi.yaml regenerated from route schemas')
  process.exit(0)
}

main().catch((err) => {
  console.error('openapi generation failed:', err)
  process.exit(1)
})
