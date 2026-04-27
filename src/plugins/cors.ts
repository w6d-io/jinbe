import fp from 'fastify-plugin'
import cors from '@fastify/cors'
import { FastifyPluginAsync } from 'fastify'
import { env } from '../config/index.js'

/**
 * CORS plugin configuration
 * Handles Cross-Origin Resource Sharing for the API
 */
const corsPlugin: FastifyPluginAsync = fp(async (fastify) => {
  // In development, allow localhost origins with credentials
  // In production, use configured origins or wildcard
  const isDev = env.NODE_ENV === 'development'

  if (isDev) {
    // In dev mode, manually add CORS headers to ALL responses
    // This fixes Swagger UI which has issues with same-origin fetch requests
    fastify.addHook('onSend', async (request, reply) => {
      const origin = request.headers.origin || 'http://localhost:3000'
      reply.header('Access-Control-Allow-Origin', origin)
      reply.header('Access-Control-Allow-Credentials', 'true')
      reply.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH')
      reply.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-ID, Cookie, X-User-Email, X-User-ID, X-User-Name')
      reply.header('Access-Control-Expose-Headers', 'X-Request-ID, Set-Cookie')
    })

    // Handle preflight OPTIONS requests
    fastify.addHook('onRequest', async (request, reply) => {
      if (request.method === 'OPTIONS') {
        const origin = request.headers.origin || 'http://localhost:3000'
        reply.header('Access-Control-Allow-Origin', origin)
        reply.header('Access-Control-Allow-Credentials', 'true')
        reply.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH')
        reply.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-ID, Cookie, X-User-Email, X-User-ID, X-User-Name')
        reply.header('Access-Control-Max-Age', '86400')
        reply.status(204).send()
      }
    })

    fastify.log.info('CORS headers enabled (dev mode - manual headers)')
  } else {
    // In production, use explicit origin allowlist
    const allowedOrigins = env.CORS_ORIGIN === '*'
      ? true  // fallback if not configured
      : env.CORS_ORIGIN.split(',').map((o: string) => o.trim())

    await fastify.register(cors, {
      origin: allowedOrigins,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Request-ID',
        'Cookie',
        'X-User-Email',
        'X-User-ID',
        'X-User-Name',
      ],
      exposedHeaders: ['X-Request-ID', 'Set-Cookie'],
    })

    fastify.log.info('CORS plugin registered')
  }
})

export default corsPlugin
