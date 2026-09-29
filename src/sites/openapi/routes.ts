import type { FastifyInstance, FastifyRequest } from 'fastify'
import { zodToJsonSchema } from 'zod-to-json-schema'
import type { ZodSchema } from 'zod'
import { actorOf, handle, nameOf, parse } from '../http.js'
import { importCommitBodySchema, importPreviewBodySchema } from './schemas.js'
import { commitImport, previewImport } from './import.service.js'
import { LIMITS } from './limits.js'
import { clientIp } from '../../utils/client-ip.js'

/**
 * /api/admin/sites/:name/import — OpenAPI → site routes (openapi-import.md §3). Same gate as a draft
 * save (sites:write): an import only ever writes the draft; saving, four-eyes and apply keep their own
 * gates. Spec reads are costly, so each actor gets 10 a minute.
 */

const config = { permission: 'sites:write' as const, rateLimit: { max: 10, timeWindow: '1 minute', keyGenerator: (r: FastifyRequest) => r.userContext?.id ?? clientIp(r) } }
const doc = (description: string, body: ZodSchema) => ({ schema: { description, tags: ['sites'], body: zodToJsonSchema(body, { target: 'openApi3' }) } })

export async function siteImportRoutes(fastify: FastifyInstance) {
  fastify.post('/:name/import/preview', {
    bodyLimit: LIMITS.bytes + 1024 * 1024,
    config,
    ...doc('Read an OpenAPI 2.0/3.0/3.1 document (content only; URL import is not available yet) and propose one route per operation: access, gate, org parameter, risk, re-import diff against the draft. Writes nothing but the uploaded bytes, kept 24 h for the commit', importPreviewBodySchema),
  }, handle(async (request) => previewImport(nameOf(request), parse(importPreviewBodySchema, request.body), actorOf(request))))

  fastify.post('/:name/import/commit', {
    bodyLimit: 2 * 1024 * 1024,
    config,
    ...doc('Merge a previewed import into the DRAFT (never a version, never an apply). specSha256 must name a spec previewed for this site (409 spec_not_previewed), baseEtag the draft the preview saw (409 stale_base); undecided rows answer 422 import_blocked', importCommitBodySchema),
  }, handle(async (request) => commitImport(nameOf(request), parse(importCommitBodySchema, request.body), actorOf(request))))
}
