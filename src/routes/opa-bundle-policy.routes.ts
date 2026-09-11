import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { scimTokenService } from '../services/scim-token.service.js'
import { policyBundle, PolicyBundleUnavailableError } from '../services/policy-bundle.service.js'
import { organisationStoreConfigured } from '../services/organisation-store.js'
import { recordEngineStatus, propagation } from '../services/engine-status.service.js'

/**
 * The bundle the authorization engine pulls: everything it decides against.
 *
 * Pulled rather than pushed, so nothing here has to know how many engine replicas exist, and one
 * that starts late catches up by itself. The engine keeps the last bundle it activated, which is
 * what lets this service be down while decisions carry on at full speed.
 *
 * Guarded by a machine credential, and that is not ceremony: this service answers on
 * `/admin/api/...` through the edge, so an unguarded route here is an internet-reachable listing of
 * every rule and everybody who satisfies one.
 */
export async function opaPolicyBundleRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', machineOnly)

  fastify.get(
    '/policy',
    {
      schema: {
        description: 'Everything the policy engine decides against, as an OPA bundle (tar.gz) rooted at ory',
        tags: ['opa'],
        response: { 401: { type: 'object', properties: { error: { type: 'string' } } } },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      if (!organisationStoreConfigured()) {
        // Nothing to serve is not the same as nobody belonging to anything. Answering an empty
        // bundle would have the engine activate it and remove everybody's access in one poll.
        return reply.status(503).send({ error: 'No membership store is configured.' })
      }

      try {
        const bundle = await policyBundle()

        // The revision doubles as the ETag: unchanged data means an unchanged hash, so a poll costs
        // a 304 and the revision the engine reports stays meaningful.
        if (request.headers['if-none-match'] === `"${bundle.revision}"`) {
          return reply.status(304).send()
        }

        return reply
          .header('content-type', 'application/gzip')
          .header('etag', `"${bundle.revision}"`)
          .header('cache-control', 'no-cache')
          .send(bundle.body)
      } catch (err) {
        // 503 and never an empty bundle, for the same reason as above: the engine treats what it
        // receives as the whole truth for this subtree.
        request.log.error({ err }, 'Could not build the policy bundle')
        const why =
          err instanceof PolicyBundleUnavailableError
            ? err.message
            : 'The policy data could not be read.'
        return reply.status(503).send({ error: why })
      }
    },
  )

  /**
   * Where each engine says which revision it is deciding against.
   *
   * OPA posts this after every bundle activation, with the same machine credential it fetches the
   * bundle with — so this route needs no second secret and inherits the guard above.
   *
   * The report also carries a large metrics dump this service has no use for. It is accepted and
   * dropped rather than refused: the alternative is an engine logging an upload failure forever
   * over a field nobody reads.
   */
  fastify.post(
    '/status',
    {
      bodyLimit: STATUS_BODY_LIMIT,
      schema: {
        description: 'Where an authorization engine reports the bundle revision it activated',
        tags: ['opa'],
        response: {
          204: { type: 'null' },
          400: { type: 'object', properties: { error: { type: 'string' } } },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const named = recordEngineStatus(request.body as never, BUNDLE_NAME)
      if (!named) return reply.status(400).send({ error: 'The report names no engine.' })
      return reply.status(204).send()
    },
  )

  /**
   * Whether a change has reached the engines yet — the question an operator asks right after a
   * write, and which nothing could answer before.
   */
  fastify.get(
    '/propagation',
    {
      schema: {
        description: 'The revision this service serves, and the revision each engine reports',
        tags: ['opa'],
      },
    },
    async (_request: FastifyRequest, reply: FastifyReply) => {
      // A bundle this service cannot build is reported as an unknown revision rather than as a
      // failure of this endpoint: what the engines hold is still worth saying.
      let serving: string | null = null
      try {
        serving = (await policyBundle()).revision
      } catch {
        serving = null
      }
      return reply.send(propagation(serving))
    },
  )
}

/** The engine's own bundle name, as configured on its side. */
const BUNDLE_NAME = 'policy'
/**
 * Generous, because the report embeds the engine's whole metrics registry — measured at ~59 KB on
 * OPA 1.19, and `status.prometheus=false` does NOT remove it. Sized to absorb growth without
 * becoming somewhere to post arbitrary payloads.
 */
const STATUS_BODY_LIMIT = 4 * 1024 * 1024

/**
 * A long-lived machine credential and nothing else — no session, no user bearer token.
 *
 * Fail-closed and deliberately uninformative: a caller learns that its credential was not accepted
 * and never why.
 */
async function machineOnly(request: FastifyRequest, reply: FastifyReply) {
  const header = request.headers.authorization
  const presented = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : ''
  const principal = presented ? await scimTokenService.verify(presented) : null
  if (!principal) {
    return reply.status(401).send({ error: 'Unauthorized' })
  }
}
