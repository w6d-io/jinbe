import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { ZodError, type z, type ZodSchema, type ZodTypeAny } from 'zod'
import { zodToJsonSchema } from 'zod-to-json-schema'
import { requireRecentMfa, requireSuperAdmin } from '../middleware/require-admin.js'
import {
  applyBodySchema, checkHostBodySchema, diffBodySchema, draftBodySchema, matchBodySchema, nameParamsSchema,
  previewBodySchema, renderTemplateBodySchema, rollbackBodySchema, saveBodySchema,
} from './schemas.js'
import * as sites from './sites.service.js'
import * as ops from './apply.service.js'
import type { Actor } from './audit.js'

/**
 * /api/admin/sites — plug a site (SERVICE_PLUG.md, site-ux.md §14.2).
 *
 * Registered inside the admin plugin, so every route already needs `admin:read`. Every write needs
 * `admin:write` (super_admin); anything that changes what the gateway serves — apply, rollback,
 * pause/resume, delete — also needs a second factor proven in the last 15 minutes.
 *
 * Bodies are validated by zod here, and only here: the JSON schemas below document them in the
 * OpenAPI spec but are not a second validator with its own coercions.
 */

const TAGS = ['sites']
const write = { preHandler: [requireSuperAdmin] }
const gateway = { preHandler: [requireSuperAdmin, requireRecentMfa] }
const doc = (description: string, body?: ZodSchema) => ({
  schema: {
    description,
    tags: TAGS,
    ...(body ? { body: zodToJsonSchema(body, { target: 'openApi3' }) } : {}),
  },
})
const docNamed = (description: string, body?: ZodSchema) => {
  const d = doc(description, body)
  return { schema: { ...d.schema, params: zodToJsonSchema(nameParamsSchema, { target: 'openApi3' }) } }
}

function actorOf(request: FastifyRequest): Actor {
  return {
    id: request.userContext?.id ?? null,
    email: request.userContext?.email ?? null,
    ip: request.ip,
    ua: (request.headers['user-agent'] as string | undefined)?.slice(0, 200) ?? null,
    sessionId: request.userContext?.sessionId ?? null,
    requestId: (request.headers['x-request-id'] as string | undefined) ?? null,
  }
}

const parse = <S extends ZodTypeAny>(schema: S, value: unknown): z.output<S> => schema.parse(value)
const nameOf = (request: FastifyRequest) => parse(nameParamsSchema, request.params).name

/** One error shape for the whole module: `{error: <code>, message, checks?, issues?}`. */
function fail(reply: FastifyReply, request: FastifyRequest, err: unknown) {
  if (err instanceof ZodError) {
    return reply.status(400).send({ error: 'invalid_request', message: 'The request is not valid', issues: err.issues })
  }
  const e = err as { statusCode?: number; code?: string; message?: string; checks?: unknown; ties?: unknown }
  const status = typeof e.statusCode === 'number' && e.statusCode >= 400 && e.statusCode < 600 ? e.statusCode : 500
  if (status >= 500 && status !== 503) request.log.error({ err }, '[sites] request failed')
  return reply.status(status).send({
    error: e.code ?? (status === 409 ? 'conflict' : status === 500 ? 'internal_error' : 'error'),
    message: status === 500 ? 'Internal error' : e.message,
    ...(e.checks ? { checks: e.checks } : {}),
    ...(e.ties ? { ties: e.ties } : {}),
  })
}

type Handler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
const handle = (fn: Handler): Handler => async (request, reply) => {
  try {
    return await fn(request, reply)
  } catch (err) {
    return fail(reply, request, err)
  }
}

export async function sitesRoutes(fastify: FastifyInstance) {
  // Documentation-only body schemas (see above): zod is the validator.
  fastify.setValidatorCompiler(() => (data) => ({ value: data }))

  fastify.get('', doc('List sites with their status'), handle(async () => sites.listSites()))

  // Static paths before `/:name` ones (Fastify prefers static segments anyway).
  fastify.post('/preview', { ...write, ...doc('Render an intent and run every check (gatekit compile + overlap against all live rules, ties, groups, host). Writes nothing; 503 when gatekit is unavailable', previewBodySchema) },
    handle(async (request) => sites.preview(parse(previewBodySchema, request.body).site)))

  fastify.get('/zones', doc('The admin-defined wildcard zones a site host can live under, with SSO (login cookie) coverage'),
    handle(async () => sites.zones()))

  fastify.post('/check-host', { ...write, ...doc('Resolve a host against the zones: zone, SSO coverage, possible exposures (zone / vanity), owner', checkHostBodySchema) },
    handle(async (request) => sites.checkHost(parse(checkHostBodySchema, request.body))))

  fastify.post('/match', { ...write, ...doc('Which gateway rule and which route a request would hit, live or with a draft (gatekit)', matchBodySchema) },
    handle(async (request) => sites.match(parse(matchBodySchema, request.body))))

  fastify.post('/render', { ...write, ...doc('Render a header/payload/claims template exactly as Oathkeeper would (gatekit)', renderTemplateBodySchema) },
    handle(async (request) => sites.renderTemplate(parse(renderTemplateBodySchema, request.body))))

  fastify.get('/:name', docNamed('A site: saved intent, version, etag, status'), handle(async (request, reply) => {
    const out = await sites.getSite(nameOf(request))
    reply.header('etag', `"${out.etag}"`)
    return out
  }))

  fastify.put('/:name', { ...write, ...docNamed('Save the intent as a new version (If-Match: the etag you edited; absent only for a new site)', saveBodySchema) },
    handle(async (request, reply) => {
      const name = nameOf(request)
      const body = parse(saveBodySchema, request.body)
      const record = await sites.save(name, body.site, { note: body.note, ifMatch: request.headers['if-match'] as string | undefined, actor: actorOf(request) })
      reply.header('etag', `"${record.etag}"`)
      return { name, version: record.version, etag: record.etag, savedAt: record.savedAt }
    }))

  fastify.delete('/:name', { ...gateway, ...docNamed('Delete a site: rules first, then its permissions; a snapshot is kept 30 days') },
    handle(async (request) => ops.remove(nameOf(request), actorOf(request))))

  fastify.get('/:name/draft', docNamed('The server-side draft'), handle(async (request) => sites.getDraft(nameOf(request))))

  fastify.put('/:name/draft', { ...write, ...docNamed('Autosave the draft (may be incomplete)', draftBodySchema) },
    handle(async (request) => sites.putDraft(nameOf(request), parse(draftBodySchema, request.body), actorOf(request))))

  fastify.delete('/:name/draft', { ...write, ...docNamed('Discard the draft') }, handle(async (request, reply) => {
    await sites.deleteDraft(nameOf(request))
    return reply.status(204).send()
  }))

  fastify.post('/:name/diff', { ...write, ...docNamed('What would change against the applied version, per artefact, with risk flags', diffBodySchema) },
    handle(async (request) => sites.diff(nameOf(request), parse(diffBodySchema, request.body ?? {}).site)))

  fastify.post('/:name/apply', { ...gateway, ...docNamed('Apply the saved version: permissions first, then the Site CR. 503 and nothing written when gatekit or Kubernetes cannot answer', applyBodySchema) },
    handle(async (request) => ops.apply(nameOf(request), parse(applyBodySchema, request.body).version, actorOf(request))))

  fastify.get('/:name/versions', docNamed('Version history (append-only)'), handle(async (request) => sites.versions(nameOf(request))))

  fastify.get('/:name/versions/:v', doc('One version, with its intent'), handle(async (request) => {
    const { v } = request.params as { v: string }
    const n = Number(v)
    if (!Number.isInteger(n) || n < 1) throw Object.assign(new Error('version must be a positive integer'), { statusCode: 400, code: 'invalid_request' })
    return sites.version(nameOf(request), n)
  }))

  fastify.post('/:name/rollback', { ...gateway, ...docNamed('Save an older version as a new one and apply it', rollbackBodySchema) },
    handle(async (request) => {
      const body = parse(rollbackBodySchema, request.body)
      return ops.rollback(nameOf(request), body.toVersion, actorOf(request), body.note)
    }))

  fastify.post('/:name/pause', { ...gateway, ...docNamed('Stop serving the site (rules removed by the operator), keep everything else') },
    handle(async (request) => ops.setPaused(nameOf(request), true, actorOf(request))))

  fastify.post('/:name/resume', { ...gateway, ...docNamed('Serve a paused site again') },
    handle(async (request) => ops.setPaused(nameOf(request), false, actorOf(request))))

  fastify.get('/:name/blast-radius', docNamed('What deleting the site would take with it'), handle(async (request) => ops.blastRadius(nameOf(request))))
}

