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
import { runBootstrap } from './bootstrap/index.js'

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

  // Health check endpoint
  fastify.get('/api/health', {
    schema: {
      description: 'Health check endpoint',
      tags: ['health'],
      response: {
        200: {
          type: 'object',
          properties: {
            status: { type: 'string' },
            uptime: { type: 'number' },
            timestamp: { type: 'string' },
            commitSha: { type: 'string' },
          },
        },
      },
    },
    handler: async (_request, reply) => {
      const { redisClientService } = await import('./services/redis-client.service.js')
      const redisHealthy = await redisClientService.isHealthy().catch(() => false)
      return reply.send({
        status: redisHealthy ? 'ok' : 'degraded',
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
 * Start the server
 */
async function start() {
  try {
    // Test database connection before starting the server (optional — skipped if DATABASE_URL not set)
    if (env.DATABASE_URL) {
      await testDatabaseConnection()
      await applyMongoValidation()
    } else {
      console.log('[startup] DATABASE_URL not set — MongoDB features disabled (clusters, backups)')
    }

    const fastify = await buildServer()

    await fastify.listen({
      port: env.PORT,
      host: env.HOST,
    })

    fastify.log.info(`Server listening on http://${env.HOST}:${env.PORT}`)
    if (env.ENABLE_SWAGGER) {
      fastify.log.info(
        `API docs available at http://${env.HOST}:${env.PORT}/docs`
      )
    }

    // Auto-bootstrap with retry — Redis/Kratos may not be ready on first boot
    const bootstrapWithRetry = async (): Promise<void> => {
      const kratosPublic = env.KRATOS_PUBLIC_URL || 'http://kratos-public:80'
      const jinbeInternal = env.JINBE_INTERNAL_URL || 'http://jinbe:8080'
      const adminEmail = process.env.ADMIN_EMAIL
      const adminPassword = process.env.ADMIN_PASSWORD || 'changeme123!'
      const adminName = process.env.ADMIN_NAME || 'Admin'

      await runBootstrap({
        logger: fastify.log,
        gitSha: env.COMMIT_SHA || 'unknown',
        version: env.APP_VERSION || 'unknown',
        config: {
          domains: {
            auth: env.AUTH_DOMAIN || '',
            app: env.APP_DOMAIN || '',
            api: env.API_DOMAIN || env.APP_DOMAIN || '',
          },
          urls: {
            kratosPublic,
            kratosAdmin: env.KRATOS_ADMIN_URL,
            loginUi: env.LOGIN_UI_URL || kratosPublic.replace(/kratos-public(:\d+)?$/, 'kratos-login-ui:80'),
            adminUi: env.ADMIN_UI_URL || jinbeInternal.replace(/jinbe(:\d+)?$/, 'admin-ui:80'),
            jinbeInternal,
          },
          admin: adminEmail ? { email: adminEmail, password: adminPassword, name: adminName } : null,
        },
      })
    }
    // Wrap bootstrap in retry
    try {
      await bootstrapWithRetry()
    } catch (err) {
      const errMsg = (err as Error)?.message || ''
      const errName = (err as Error)?.name || ''
      if (errMsg.includes('ECONNREFUSED') || errMsg.includes('max retries') || errName.includes('MaxRetries')) {
        fastify.log.info('Redis not ready — scheduling bootstrap retry in background')
        const retry = async (attempt: number): Promise<void> => {
          try {
            await bootstrapWithRetry()
          } catch (retryErr) {
            if (attempt < 15) {
              const d = Math.min(attempt * 3000, 15000)
              fastify.log.info({ attempt }, `Bootstrap retry ${attempt} — next in ${d}ms`)
              await new Promise(r => setTimeout(r, d))
              return retry(attempt + 1)
            }
            fastify.log.error({ err: retryErr }, 'Bootstrap failed after 15 retries')
          }
        }
        // Run in background — don't block server startup
        retry(1).catch(() => {})
      } else {
        fastify.log.warn({ err }, 'Bootstrap failed')
      }
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
