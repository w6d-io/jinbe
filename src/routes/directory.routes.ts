import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { scimTokenService } from '../services/scim-token.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { organisationsForSubject, organisationsById, organisationStoreConfigured } from '../services/organisation-store.js'

/**
 * What this service knows about somebody OTHER than the caller.
 *
 * Every other route here answers about whoever is asking. This one answers about a named subject,
 * which is the whole reason it exists: the step that mints a token holds the subject and no
 * credential belonging to them, so it cannot ask a directory that only ever answers about its
 * caller. That limitation is what forced a remembered choice to be kept in one process's memory,
 * shared between clients and lost on every redeploy.
 *
 * Because it answers about anybody, the credential matters more than the body. It takes a long-lived
 * machine token — hashed at rest, compared in constant time — and nothing else: not a session
 * cookie, not a user's bearer token. A route that answered a browser would let whoever holds one
 * enumerate the directory.
 *
 * Reads only. Nothing here can change a membership; the routes that do are guarded by the caller's
 * own permissions, which is the check this route deliberately does not have.
 */
export async function directoryRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', machineOnly)

  fastify.get(
    '/organisations',
    {
      schema: {
        description: "The organisations a subject belongs to — for a caller acting on nobody's behalf",
        tags: ['directory'],
        querystring: {
          type: 'object',
          required: ['subject'],
          properties: { subject: { type: 'string', minLength: 1 } },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              subject: { type: 'string' },
              organisations: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    name: { type: 'string' },
                    tenant: { type: 'string' },
                  },
                },
              },
            },
          },
          401: { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } },
          503: { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } },
        },
      },
    },
    async (request: FastifyRequest<{ Querystring: { subject: string } }>, reply: FastifyReply) => {
      const { subject } = request.query

      if (!organisationStoreConfigured()) {
        // Refused, never answered as an empty set: a caller cannot tell "belongs to nothing" from
        // "this deployment does not keep them here", and the first would silently narrow a token.
        return reply.status(503).send({
          error: 'Service Unavailable',
          message: 'This deployment does not hold organisation records.',
        })
      }

      try {
        const ids = await organisationsForSubject(subject)
        const held = await organisationsById(ids)

        return reply.send({
          subject,
          // The ids the subject belongs to, described where a record exists. An id with no record
          // is still returned, named after itself: dropping it would quietly narrow the answer.
          organisations: ids.map((id) => {
            const record = held.find((o) => o.id === id)
            return { id, name: record?.name ?? id, tenant: record?.tenant ?? '' }
          }),
        })
      } catch (err) {
        request.log.error({ err, subject }, 'Could not resolve the organisations of a subject')
        return reply.status(503).send({
          error: 'Service Unavailable',
          message: 'Unable to resolve organisations. Please try again later.',
        })
      }
    }
  )
}

/**
 * A machine token, and nothing else.
 *
 * Fail-closed and deliberately uninformative: a caller learns that its credential was not accepted
 * and never why, because the difference between "absent" and "unknown" is a probing aid.
 */
async function machineOnly(request: FastifyRequest, reply: FastifyReply) {
  const header = request.headers.authorization
  const presented = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : ''
  const principal = presented ? await scimTokenService.verify(presented) : null

  if (!principal) {
    auditEventService
      .emit({
        category: 'access',
        verb: 'deny',
        target: `${request.method} ${request.url}`,
        result: 'denied',
        actor: { email: null, ip: request.ip, ua: (request.headers['user-agent'] as string) || null },
        method: request.method,
        path: request.url,
        reason: 'machine_credential_required',
      })
      .catch(() => {})

    return reply.status(401).send({
      error: 'Unauthorized',
      message: 'A machine credential is required.',
    })
  }

  request.scimToken = principal
}
