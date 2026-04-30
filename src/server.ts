import Fastify from 'fastify'
import { env } from './config/index.js'
import { errorHandler } from './middleware/error-handler.js'
import { requestIdMiddleware } from './middleware/request-id.js'
import { extractIdentity } from './middleware/identity-extractor.js'
import { requireAuth } from './middleware/require-auth.js'
import { auditLogger } from './middleware/audit-logger.js'

// Plugins
import corsPlugin from './plugins/cors.js'
import helmetPlugin from './plugins/helmet.js'
import rateLimitPlugin from './plugins/rate-limit.js'
import swaggerPlugin from './plugins/swagger.js'

// Routes
import { backupRoutes } from './routes/backup.routes.js'
import { clusterRoutes } from './routes/cluster.routes.js'
import { databaseRoutes } from './routes/database.routes.js'
import { backupItemRoutes } from './routes/backup-item.routes.js'
import { databaseAPIRoutes } from './routes/database-api.routes.js'
import { whoamiRoutes } from './routes/whoami.routes.js'
import { adminRoutes } from './routes/admin.routes.js'
import { jobRoutes } from './routes/job.routes.js'
import { rbacRoutes, rbacOpalRoutes } from './routes/rbac.routes.js'
import { rbacBundleRoutes } from './routes/rbac-bundle.routes.js'
import { opaBundleRoutes } from './routes/opa-bundle.routes.js'
import { oathkeeperRoutes } from './routes/oathkeeper.routes.js'
import { auditRoutes } from './routes/audit.routes.js'
import { organizationUserRoutes } from './routes/organization-user.routes.js'
import { testDatabaseConnection, applyMongoValidation } from './utils/prisma.js'
import { waitForBootstrap, BootstrapTimeoutError } from './bootstrap/wait-for-bootstrap.js'
import { MarkerCorruptError } from './bootstrap/marker.js'

// Set true after waitForBootstrap resolves. Health endpoint returns 503
// until then so the Deployment startupProbe absorbs the wait window.
let bootstrapReady = false

/**
 * Build Fastify server instance
 */
export async function buildServer() {
  const fastify = Fastify({
    logger: {
      level: env.LOG_LEVEL,
      transport:
        env.NODE_ENV === 'development'
          ? {
              target: 'pino-pretty',
              options: {
                translateTime: 'HH:MM:ss Z',
                ignore: 'pid,hostname',
              },
            }
          : undefined,
      // Add base labels for Prometheus scraping
      base: {
        service: 'jinbe',
        environment: env.NODE_ENV,
      },
    },
    requestIdLogLabel: 'requestId',
    disableRequestLogging: false,
    trustProxy: true,
  })

  // Set error handler
  fastify.setErrorHandler(errorHandler)

  // CORS must be registered FIRST to ensure headers are added even on 401 errors
  await fastify.register(corsPlugin)

  // Add request ID to all requests
  fastify.addHook('onRequest', requestIdMiddleware)

  // Extract user identity from Kratos session or proxy headers
  fastify.addHook('onRequest', extractIdentity)

  // Require authentication for all routes except public ones (health, whoami)
  fastify.addHook('onRequest', requireAuth)

  // Register other plugins
  await fastify.register(rateLimitPlugin)
  await fastify.register(swaggerPlugin)

  // Register helmet after swagger to avoid CSP issues
  await fastify.register(helmetPlugin)

  // Audit logger - log all actions after response (after routes)
  fastify.addHook('onResponse', auditLogger)

  // Health check endpoint. Returns 503 until the bootstrap marker has been
  // observed, so Kubernetes startupProbe stays unsatisfied until ready.
  fastify.get('/api/health', {
    schema: {
      description: 'Health check endpoint',
      tags: ['health'],
    },
    handler: async (_request, reply) => {
      const { redisClientService } = await import('./services/redis-client.service.js')
      const redisHealthy = await redisClientService.isHealthy().catch(() => false)
      const status = bootstrapReady && redisHealthy ? 'ok' : bootstrapReady ? 'degraded' : 'starting'
      const code = bootstrapReady ? 200 : 503
      return reply.status(code).send({
        status,
        bootstrapReady,
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        commitSha: env.COMMIT_SHA || 'unknown',
        redis: redisHealthy ? 'connected' : 'disconnected',
      })
    },
  })

  await fastify.register(
    async function (api) {
      await api.register(whoamiRoutes)
      await api.register(clusterRoutes, { prefix: '/clusters' })
      await api.register(databaseRoutes, { prefix: '/databases' })
      await api.register(backupRoutes, { prefix: '/backups' })
      await api.register(backupItemRoutes, { prefix: '/backup-items' })
      await api.register(databaseAPIRoutes, { prefix: '/database-apis' })
      await api.register(adminRoutes, { prefix: '/admin' })
      await api.register(rbacOpalRoutes, { prefix: '/admin/rbac' })  // Public OPAL data endpoints (no auth)
      await api.register(rbacRoutes, { prefix: '/admin/rbac' })      // Admin RBAC management (auth required)
      await api.register(rbacBundleRoutes, { prefix: '/admin/rbac' }) // Bundle export/import (super_admin)
      await api.register(auditRoutes, { prefix: '/admin/audit' })
      await api.register(organizationUserRoutes, { prefix: '/organizations/:organizationId' })
      await api.register(opaBundleRoutes, { prefix: '/opa' })
      await api.register(oathkeeperRoutes, { prefix: '/oathkeeper' })
      await api.register(jobRoutes)
    },
    { prefix: '/api' }
  )
  return fastify
}

/**
 * Start the server.
 *
 * The bootstrap CLI seeds RBAC config and writes a marker; this process only
 * starts serving traffic once the marker is observed. Until then, /api/health
 * returns 503 so Kubernetes startupProbe holds the pod off readiness.
 */
async function start() {
  try {
    if (env.DATABASE_URL) {
      await testDatabaseConnection()
      await applyMongoValidation()
    } else {
      console.log('[startup] DATABASE_URL not set — MongoDB features disabled (clusters, backups)')
    }

    const fastify = await buildServer()

    // Listen first so startupProbe can hit /api/health (which returns 503 until ready).
    await fastify.listen({
      port: env.PORT,
      host: env.HOST,
    })
    fastify.log.info(`Server listening on http://${env.HOST}:${env.PORT}`)
    if (env.ENABLE_SWAGGER) {
      fastify.log.info(`API docs available at http://${env.HOST}:${env.PORT}/docs`)
    }

    // Block until the bootstrap Job has written the marker. Default budget
    // 6 minutes — matches the chart's startupProbe (failureThreshold: 72,
    // periodSeconds: 5).
    try {
      const marker = await waitForBootstrap({ logger: fastify.log })
      bootstrapReady = true
      fastify.log.info(
        { schemaVersion: marker.schemaVersion, gitSha: marker.gitSha },
        'Bootstrap ready — serving traffic',
      )
    } catch (err) {
      if (err instanceof BootstrapTimeoutError) {
        fastify.log.error({ elapsedMs: err.elapsedMs }, 'Bootstrap timeout — exiting')
        process.exit(2)
      }
      if (err instanceof MarkerCorruptError) {
        fastify.log.error({ raw: err.raw }, 'Bootstrap marker corrupt — exiting')
        process.exit(5)
      }
      throw err
    }
  } catch (err) {
    console.error('Failed to start server:', err)
    process.exit(1)
  }
}

// Handle graceful shutdown
const signals = ['SIGINT', 'SIGTERM']
signals.forEach((signal) => {
  process.on(signal, async () => {
    console.log(`Received ${signal}, shutting down gracefully...`)
    try {
      const { redisClientService } = await import('./services/redis-client.service.js')
      await redisClientService.disconnect()
    } catch { /* ignore */ }
    process.exit(0)
  })
})

// Start server if this is the main module
if (import.meta.url === `file://${process.argv[1]}`) {
  start()
}
