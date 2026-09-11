import { FastifyInstance } from 'fastify'
import { serviceIdentity } from '../telemetry/identity.js'

/**
 * What a browser needs to report what happens in it — served by this API rather than baked into the
 * page.
 *
 * One place configures the whole stack. The console inherits the environment and version this
 * service already carries, so a browser session and the request it makes cannot be filed under
 * different versions of the same deployment — which is the failure that makes a correlated trace
 * useless exactly when it matters.
 *
 * PUBLIC, and it holds nothing private: a collector address reaches the browser either way, and a
 * console that cannot read this before signing in could not report a failure to sign in.
 *
 * An empty answer is the OFF position. A deployment that configures nothing gets `{}`, and the
 * console starts no telemetry — which is what most deployments of an open-source project want.
 */
export async function telemetryRoutes(fastify: FastifyInstance) {
  fastify.get(
    '/telemetry',
    {
      schema: {
        description: 'Browser telemetry settings. Empty when none is configured.',
        tags: ['health'],
        response: {
          200: {
            type: 'object',
            properties: {
              faroUrl: { type: 'string' },
              serviceName: { type: 'string' },
              version: { type: 'string' },
              environment: { type: 'string' },
            },
          },
        },
      },
    },
    async (_request, reply) => {
      const url = process.env.BROWSER_FARO_URL
      if (!url) return reply.send({})

      const identity = serviceIdentity()
      return reply.send({
        faroUrl: url,
        // Named for the browser, not for this service: they are two services in one trace, and one
        // name over both makes a page load and an API call indistinguishable.
        serviceName: process.env.BROWSER_SERVICE_NAME || 'kuma',
        ...(identity.version ? { version: identity.version } : {}),
        ...(identity.env ? { environment: identity.env } : {}),
      })
    },
  )
}
