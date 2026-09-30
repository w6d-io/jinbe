import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { zodToJsonSchema } from 'zod-to-json-schema'
import { open } from '../policy/route-access.js'
import { requireHomeScope, viewFor, canSee, type HomeScope, type HomeView } from './scope.js'
import { buildHome, buildModules, forbidden } from './service.js'
import { HOME_MODULES, homeQuerySchema, homeResponseSchema, moduleEnvelopeSchema, type HomeModuleName } from './types.js'
import { permissionRefusalProperties } from '../schemas/response-schemas.js'

/**
 * /api/home — the console's briefing (home-data §3, §11).
 *
 * Registered OUTSIDE /api/admin: that plugin's requireAdmin would lock out support and org admins.
 * Its own guard resolves the caller's scope from OPA; every module is narrowed server-side and the
 * ones the caller may not see are omitted. `?org=` is checked against that scope (403 outside it).
 *
 * The schemas below document the response for the OpenAPI file; zod is what validates the query.
 */

const TAGS = ['home']
const json = (schema: Parameters<typeof zodToJsonSchema>[0]) => zodToJsonSchema(schema, { target: 'openApi3' })
const error = { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' }, code: { type: 'string' }, reason: { type: 'string' }, ...permissionRefusalProperties } }

const CACHE_CONTROL = 'private, max-age=15'

function scopeAndView(request: FastifyRequest, reply: FastifyReply): { scope: HomeScope; view: HomeView; window: '24h' | '7d'; org: string | null } | null {
  const q = homeQuerySchema.safeParse(request.query ?? {})
  if (!q.success) {
    reply.status(400).send({ error: 'invalid_request', message: q.error.issues.map((i) => `${i.path.join('.') || 'query'}: ${i.message}`).join('; ') })
    return null
  }
  const scope = request.homeScope as HomeScope
  const view = viewFor(scope, q.data.org)
  if (!view) {
    reply.status(403).send({ error: 'org_out_of_scope', message: 'You can only see organisations you administer.' })
    return null
  }
  return { scope, view, window: q.data.window, org: q.data.org ?? null }
}

export async function homeRoutes(fastify: FastifyInstance) {
  // Documentation-only schemas: zod validates, the handlers serialise.
  fastify.setValidatorCompiler(() => (data) => ({ value: data }))
  fastify.setSerializerCompiler(() => (data) => JSON.stringify(data))

  const guard = requireHomeScope()
  const querystring = json(homeQuerySchema)

  fastify.get('', {
    ...open('self'), // its own scope guard narrows every module to the caller
    preHandler: guard,
    schema: {
      description: 'The Home briefing: every module the caller may see, each with its own status, freshness and sources',
      tags: TAGS,
      querystring,
      response: { 200: json(homeResponseSchema), 400: error, 401: error, 403: error, 503: error },
    },
  }, async (request, reply) => {
    const ctx = scopeAndView(request, reply)
    if (!ctx) return reply
    const body = await buildHome(ctx.scope, ctx.view, ctx.window, ctx.org)
    return reply.header('Cache-Control', CACHE_CONTROL).send(body)
  })

  fastify.get('/:module', {
    ...open('self'), // its own scope guard narrows every module to the caller
    preHandler: guard,
    schema: {
      description: 'One Home module (retry after unavailable, or refresh a single tile). 403 with status "forbidden" for a module the caller may not see.',
      tags: TAGS,
      querystring,
      params: { type: 'object', required: ['module'], properties: { module: { type: 'string', enum: [...HOME_MODULES] } } },
      response: { 200: json(moduleEnvelopeSchema), 400: error, 401: error, 403: json(moduleEnvelopeSchema), 404: error, 503: error },
    },
  }, async (request, reply) => {
    const name = (request.params as { module: string }).module
    if (!(HOME_MODULES as readonly string[]).includes(name)) {
      return reply.status(404).send({ error: 'not_found', message: `No Home module ${name}` })
    }
    const ctx = scopeAndView(request, reply)
    if (!ctx) return reply
    const module = name as HomeModuleName
    if (!canSee(module, ctx.scope, ctx.view)) return reply.status(403).send(forbidden())
    const out = await buildModules(ctx.scope, ctx.view, ctx.window, [module])
    return reply.header('Cache-Control', CACHE_CONTROL).send(out[module])
  })
}
