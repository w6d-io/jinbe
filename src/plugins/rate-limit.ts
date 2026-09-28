import fp from 'fastify-plugin'
import rateLimit from '@fastify/rate-limit'
import { env } from '../config/index.js'
import { FastifyPluginAsync } from 'fastify'
import { clientIp } from '../utils/client-ip.js'

/**
 * Rate limiting plugin
 * Prevents abuse by limiting requests per IP
 */
const rateLimitPlugin: FastifyPluginAsync = fp(async (fastify) => {
  await fastify.register(rateLimit, {
    max: env.RATE_LIMIT_MAX,
    timeWindow: env.RATE_LIMIT_TIME_WINDOW,
    keyGenerator: (request) => clientIp(request),
    errorResponseBuilder: () => ({
      error: 'Too Many Requests',
      message: 'Rate limit exceeded, please try again later',
      statusCode: 429,
    }),
  })

  fastify.log.info('Rate limit plugin registered')
})

export default rateLimitPlugin
