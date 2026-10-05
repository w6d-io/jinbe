import type { FastifyInstance } from 'fastify'
import type { ZodSchema } from 'zod'
import { zodToJsonSchema } from 'zod-to-json-schema'
import type { Permission } from '../policy/catalog.js'
import {
  applyBodySchema, checkHostBodySchema, createZoneBodySchema, diffBodySchema, draftBodySchema, matchBodySchema, nameParamsSchema,
  previewBodySchema, renderTemplateBodySchema, rollbackBodySchema, saveBodySchema, suggestZoneBodySchema, updateZoneBodySchema, zoneParamsSchema,
} from './schemas.js'
import * as zones from './zones.service.js'
import * as gateways from './gateways.service.js'
import * as sites from './sites.service.js'
import * as ops from './apply.service.js'
import { actorOf, handle, nameOf, parse } from './http.js'
import { assertGatesAuthenticated } from './checks.js'
import { siteOpsRoutes } from './ops.routes.js'
import { migrationRoutes } from './migration/routes.js'
import { siteImportRoutes } from './openapi/routes.js'
import { siteLifecycleRoutes } from './lifecycle.routes.js'
import { siteSignUpRoutes } from './signup/routes.js'
import { setEphemeral } from './ephemeral.js'
import { sitesConfig } from './config.js'

/**
 * /api/admin/sites — plug a site (SERVICE_PLUG.md, site-ux.md §14.2).
 *
 * Each route names its catalogue permission as the first argument of `doc`: reading `sites:read`,
 * drafts, saves, requests (apply and deletion) and TTL renewals `sites:write`, anything that changes what the gateway serves — apply,
 * rollback, pause/resume, restore — `sites:apply`, deleting and deciding a deletion request
 * `sites:delete`, zones `zones:*`; the
 * catalogue adds the second factor proven in the last 15 minutes where it says stepUp.
 *
 * Bodies are validated by zod here, and only here: the JSON schemas below document them in the
 * OpenAPI spec but are not a second validator with its own coercions.
 */

const TAGS = ['sites']
const doc = (permission: Permission, description: string, body?: ZodSchema) => ({
  config: { permission },
  schema: {
    description,
    tags: TAGS,
    ...(body ? { body: zodToJsonSchema(body, { target: 'openApi3' }) } : {}),
  },
})
const docNamed = (permission: Permission, description: string, body?: ZodSchema) => {
  const d = doc(permission, description, body)
  return { ...d, schema: { ...d.schema, params: zodToJsonSchema(nameParamsSchema, { target: 'openApi3' }) } }
}

export async function sitesRoutes(fastify: FastifyInstance) {
  // Documentation-only body schemas (see above): zod is the validator.
  fastify.setValidatorCompiler(() => (data) => ({ value: data }))

  fastify.get('', doc('sites:read', 'List sites with their status and two-step sign-in bar (secondFactor: scope, routes, clients, minAal, summary — of the saved version)'), handle(async () => sites.listSites()))

  // Static paths before `/:name` ones (Fastify prefers static segments anyway).
  fastify.post('/preview', { ...doc('sites:write', 'Render an intent and run every check (gatekit compile + overlap against all live rules, ties, groups, host). Writes nothing; 503 when gatekit is unavailable', previewBodySchema) },
    handle(async (request) => sites.preview(parse(previewBodySchema, request.body).site)))

  fastify.get('/zones', doc('zones:read', 'The admin-defined wildcard zones a site host can live under, with SSO (login cookie) coverage'),
    handle(async () => sites.zones()))

  // Zones (zones.auth.w6d.io, cluster-scoped): creating or deleting one changes what the platform
  // serves, so it is gated like an apply.
  fastify.get('/zones/:name', doc('zones:read', 'A zone: spec, operator status (IngressReady, CertificateReady, DomainTaken), the sites it serves'),
    handle(async (request) => zones.getZone(parse(zoneParamsSchema, request.params).name)))

  fastify.post('/zones', { ...doc('zones:write', 'Create a zone (Zone CR): domain under SITES_ZONE_ALLOWED_PARENTS, TLS default | issuer | secret. The operator makes the wildcard Ingress and certificate', createZoneBodySchema) },
    handle(async (request, reply) => {
      const out = await zones.createZone(parse(createZoneBodySchema, request.body), actorOf(request))
      return reply.status(201).send(out)
    }))

  fastify.patch('/zones/:name', { ...doc('zones:write', 'Change a zone\'s exposure (never its domain): ingress wildcard | per-site | none, gateway (null detaches), TLS. ingress none is refused (409 dns_not_on_gateway, per-host checks) while a site host does not resolve to the Gateway, unless confirm', updateZoneBodySchema) },
    handle(async (request) => zones.updateZone(parse(zoneParamsSchema, request.params).name, parse(updateZoneBodySchema, request.body), actorOf(request))))

  fastify.get('/gateways', doc('sites:read', 'The Gateway API Gateways a zone may be attached to (SITES_GATEWAYS): listeners, addresses, and whether their WAF and IP reputation policies are in force'),
    handle(async () => gateways.listGateways()))

  fastify.delete('/zones/:name', { ...doc('zones:delete', 'Delete a zone; refused (409, with the sites) while a saved site has a host under it') },
    handle(async (request) => zones.deleteZone(parse(zoneParamsSchema, request.params).name, actorOf(request))))

  fastify.post('/zones/suggest', doc('zones:read', 'The zone to create for a host outside every zone: its parent domain, allow-list, wildcard DNS probe, TLS choices, SSO coverage. Writes nothing', suggestZoneBodySchema),
    handle(async (request) => zones.suggestZone(parse(suggestZoneBodySchema, request.body).host)))

  fastify.post('/check-host', { ...doc('sites:write', 'Resolve a host against the zones: zone, SSO coverage, possible exposures (zone / vanity), owner', checkHostBodySchema) },
    handle(async (request) => sites.checkHost(parse(checkHostBodySchema, request.body))))

  fastify.get('/platform', doc('sites:read', 'This environment: name, production flag, four-eyes mode, expected rule-load time, zones'),
    handle(async () => sites.platformView()))

  fastify.get('/deleted', doc('sites:read', 'Deleted sites whose snapshot is kept (30 days)'), handle(async () => sites.deletedSites()))

  fastify.post('/match', { ...doc('sites:read', 'Which gateway rule and which route a request would hit, live or with a draft (gatekit)', matchBodySchema) },
    handle(async (request) => sites.match(parse(matchBodySchema, request.body))))

  fastify.post('/render', { ...doc('sites:read', 'Render a header/payload/claims template exactly as Oathkeeper would (gatekit)', renderTemplateBodySchema) },
    handle(async (request) => sites.renderTemplate(parse(renderTemplateBodySchema, request.body))))

  fastify.get('/:name', docNamed('sites:read', 'A site: saved intent, its two-step sign-in bar (secondFactor), version, etag, status'), handle(async (request, reply) => {
    const out = await sites.getSite(nameOf(request))
    reply.header('etag', `"${out.etag}"`)
    return out
  }))

  fastify.put('/:name', { ...docNamed('sites:write', 'Save the intent as a new version (If-Match: the etag you edited; absent only for a new site). ephemeral {ttl?}: paused automatically when the TTL passes (1 hour to 7 days, 24 hours by default), counted from this save; null: permanent again; absent: unchanged', saveBodySchema) },
    handle(async (request, reply) => {
      const name = nameOf(request)
      // A gate that lets nobody in is 422 (like a draft), not a schema 400.
      assertGatesAuthenticated((request.body as { site?: unknown } | null)?.site)
      const body = parse(saveBodySchema, request.body)
      const record = await sites.save(name, body.site, { note: body.note, ifMatch: request.headers['if-match'] as string | undefined, actor: actorOf(request) })
      const ephemeral = body.ephemeral === undefined ? undefined : await setEphemeral(name, body.ephemeral, actorOf(request))
      reply.header('etag', `"${record.etag}"`)
      return { name, version: record.version, etag: record.etag, savedAt: record.savedAt, ...(ephemeral !== undefined ? { ephemeral } : {}) }
    }))

  fastify.delete('/:name', { ...docNamed('sites:delete', 'Delete a site: rules first, then its permissions; a snapshot is kept 30 days') },
    handle(async (request) => ops.remove(nameOf(request), actorOf(request))))

  fastify.post('/:name/restore', { ...docNamed('sites:apply', 'Restore a deleted site from its snapshot, saved but not applied') },
    handle(async (request) => ops.restore(nameOf(request))))

  fastify.get('/:name/draft', docNamed('sites:read', 'The server-side draft, with its etag (also the ETag header): send it as If-Match on the next autosave'), handle(async (request, reply) => {
    const draft = await sites.getDraft(nameOf(request))
    reply.header('etag', `"${draft.etag}"`)
    return draft
  }))

  fastify.put('/:name/draft', { ...docNamed('sites:write', 'Autosave the draft (may be incomplete). If-Match: the draft etag you edited; a stale one is 412 stale_draft with `current` {etag, updatedBy, updatedAt} and the ETag header. If-None-Match: * when you loaded no draft: 412 stale_draft the same way if one exists now. Without If-Match over an existing draft: accepted and logged (SITES_DRAFT_IF_MATCH=warn, the default) or 428 (require). Answers the new etag', draftBodySchema) },
    handle(async (request, reply) => {
      const name = nameOf(request)
      const ifMatch = request.headers['if-match'] as string | undefined
      // Only `*` means anything here: "write only if there is no draft".
      const ifNoneMatch = (request.headers['if-none-match'] as string | undefined)?.trim() === '*'
      const requireIfMatch = sitesConfig().SITES_DRAFT_IF_MATCH === 'require'
      if (!ifMatch && !ifNoneMatch && !requireIfMatch) request.log.warn({ site: name }, '[sites] draft autosave without If-Match (overwrites any other draft)')
      const draft = await sites.putDraft(name, parse(draftBodySchema, request.body), actorOf(request), { ifMatch, ifNoneMatch, requireIfMatch })
      reply.header('etag', `"${draft.etag}"`)
      return draft
    }))

  fastify.delete('/:name/draft', { ...docNamed('sites:write', 'Discard the draft') }, handle(async (request, reply) => {
    await sites.deleteDraft(nameOf(request), actorOf(request))
    return reply.status(204).send()
  }))

  fastify.post('/:name/diff', { ...docNamed('sites:write', 'What would change against the applied version, per artefact, with risk flags', diffBodySchema) },
    handle(async (request) => sites.diff(nameOf(request), parse(diffBodySchema, request.body ?? {}).site)))

  fastify.post('/:name/apply', { ...docNamed('sites:apply', 'Apply the saved version: permissions first, then the Site CR. 503 and nothing written when gatekit or Kubernetes cannot answer. 422 unconfirmed_findings (with `findings`) while a security finding is an error, or a confirm finding\'s code is not in `acknowledge`', applyBodySchema) },
    handle(async (request) => {
      const body = parse(applyBodySchema, request.body)
      return ops.apply(nameOf(request), body.version, actorOf(request), body.acknowledge)
    }))

  fastify.get('/:name/versions', docNamed('sites:read', 'Version history (append-only)'), handle(async (request) => sites.versions(nameOf(request))))

  fastify.get('/:name/versions/:v', doc('sites:read', 'One version, with its intent'), handle(async (request) => {
    const { v } = request.params as { v: string }
    const n = Number(v)
    if (!Number.isInteger(n) || n < 1) throw Object.assign(new Error('version must be a positive integer'), { statusCode: 400, code: 'invalid_request' })
    return sites.version(nameOf(request), n)
  }))

  fastify.post('/:name/rollback', { ...docNamed('sites:apply', 'Save an older version as a new one and apply it', rollbackBodySchema) },
    handle(async (request) => {
      const body = parse(rollbackBodySchema, request.body)
      return ops.rollback(nameOf(request), body.toVersion, actorOf(request), body.note)
    }))

  fastify.post('/:name/pause', { ...docNamed('sites:apply', 'Stop serving the site (rules removed by the operator), keep everything else') },
    handle(async (request) => ops.setPaused(nameOf(request), true, actorOf(request))))

  fastify.post('/:name/resume', { ...docNamed('sites:apply', 'Serve a paused site again') },
    handle(async (request) => ops.setPaused(nameOf(request), false, actorOf(request))))

  fastify.get('/:name/blast-radius', docNamed('sites:read', 'What deleting the site would take with it'), handle(async (request) => ops.blastRadius(nameOf(request))))

  // Day-2 (status, drift, timelines, requests, logo), lifecycle (TTL, deletion requests), OpenAPI
  // import, and the one-time migration.
  await fastify.register(siteOpsRoutes)
  await fastify.register(siteLifecycleRoutes)
  await fastify.register(siteSignUpRoutes)
  await fastify.register(siteImportRoutes)
  await fastify.register(migrationRoutes, { prefix: '/migration' })
}

