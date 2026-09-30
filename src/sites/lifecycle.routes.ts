import type { FastifyInstance } from 'fastify'
import { z, type ZodSchema } from 'zod'
import { zodToJsonSchema } from 'zod-to-json-schema'
import type { Permission } from '../policy/catalog.js'
import { actorOf, handle, nameOf, parse } from './http.js'
import { deletionRequestBodySchema, renewTtlBodySchema } from './schemas.js'
import { renewTtl } from './ephemeral.js'
import { approveDeletionRequest, createDeletionRequest, listDeletionRequests, pendingDeletionRequests, rejectDeletionRequest } from './deletion-requests.js'

/**
 * Lifecycle routes under /api/admin/sites (wave 19): renewing an ephemeral site's TTL, and deletion
 * requests. Asking (a TTL, a deletion) is sites:write, which a key may hold; deciding a deletion is
 * sites:delete — `delegable: 'never'` and step-up in the catalogue, so only a person in a browser.
 */

const TAGS = ['sites']
const doc = (permission: Permission, description: string, body?: ZodSchema) => ({
  config: { permission },
  schema: { description, tags: TAGS, ...(body ? { body: zodToJsonSchema(body, { target: 'openApi3' }) } : {}) },
})

const idParams = z.object({ id: z.string().min(1).max(64) })
const decideBody = z.object({ reason: z.string().max(280).optional() }).strict()
const listQuery = z.object({ state: z.enum(['pending', 'approved', 'rejected', 'cancelled']).optional(), site: z.string().max(40).optional() })

export async function siteLifecycleRoutes(fastify: FastifyInstance) {
  fastify.post('/:name/ttl', doc('sites:write', 'Extend an ephemeral site: its expiry becomes now + ttl (seconds or 30m/12h/3d, 1 hour to 7 days; its own TTL when left out). An expired site stays paused: resuming it is sites:apply. 409 not_ephemeral for a permanent site', renewTtlBodySchema),
    handle(async (request) => renewTtl(nameOf(request), parse(renewTtlBodySchema, request.body ?? {}).ttl, actorOf(request))))

  fastify.post('/:name/deletion-requests', doc('sites:write', 'Ask for the site to be deleted; a person holding sites:delete, other than the requester, decides. 409 deletion_request_pending while one is open', deletionRequestBodySchema),
    handle(async (request, reply) => {
      const out = await createDeletionRequest(nameOf(request), parse(deletionRequestBodySchema, request.body ?? {}), actorOf(request))
      return reply.status(201).send(out)
    }))

  fastify.get('/deletion-requests', doc('sites:read', 'Deletion requests, newest first (?state=pending|approved|rejected|cancelled, ?site=)'),
    handle(async (request) => listDeletionRequests(parse(listQuery, request.query ?? {}))))

  fastify.get('/deletion-requests/pending', doc('sites:read', 'The deletion inbox: pending requests, oldest first, with requestedByYou (the requester cannot approve their own)'),
    handle(async (request) => pendingDeletionRequests(actorOf(request))))

  fastify.post('/deletion-requests/:id/approve', doc('sites:delete', 'Approve a deletion request: deletes the site as the approver (rules first, then its permissions; a 30-day snapshot). Four-eyes: 403 second_approver_required for the requester. Never through a key'),
    handle(async (request) => approveDeletionRequest(parse(idParams, request.params).id, actorOf(request))))

  fastify.post('/deletion-requests/:id/reject', doc('sites:delete', 'Reject a deletion request, with an optional reason. Never through a key', decideBody),
    handle(async (request) => rejectDeletionRequest(parse(idParams, request.params).id, actorOf(request), parse(decideBody, request.body ?? {}).reason)))
}
