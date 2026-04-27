import fp from 'fastify-plugin'
import helmet from '@fastify/helmet'
import { FastifyPluginAsync } from 'fastify'

/**
 * Helmet plugin configuration
 * Adds security headers to responses
 * CSP is disabled for API usage - enable in production with proper directives
 */
const helmetPlugin: FastifyPluginAsync = fp(async (fastify) => {
  await fastify.register(helmet, {
    contentSecurityPolicy: false, // Disable CSP for API
    crossOriginResourcePolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginEmbedderPolicy: false,
  })

  fastify.log.info('Helmet plugin registered (CSP disabled)')
})

export default helmetPlugin
