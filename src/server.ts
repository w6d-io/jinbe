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
import { meRoutes } from './routes/me.routes.js'
import { adminRoutes } from './routes/admin.routes.js'
import { jobRoutes } from './routes/job.routes.js'
import { rbacRoutes, rbacOpalRoutes } from './routes/rbac.routes.js'
import { rbacBundleRoutes } from './routes/rbac-bundle.routes.js'
import { authConfigRoutes } from './routes/auth-config.routes.js'
import { opaBundleRoutes } from './routes/opa-bundle.routes.js'
import { oathkeeperRoutes } from './routes/oathkeeper.routes.js'
import { auditRoutes } from './routes/audit.routes.js'
import { webhookRoutes } from './routes/webhook.routes.js'
import { organizationUserRoutes } from './routes/organization-user.routes.js'
import { directoryRoutes } from './routes/directory.routes.js'
import { opaPolicyBundleRoutes } from './routes/opa-bundle-policy.routes.js'
import { apiKeyRoutes, apiKeyInternalRoutes } from './routes/api-key.routes.js'
import { scimRoutes } from './routes/scim.routes.js'
import { recertRoutes } from './routes/recert.routes.js'
import { testDatabaseConnection, applyMongoValidation } from './utils/prisma.js'
import { waitForBootstrap, BootstrapTimeoutError } from './bootstrap/wait-for-bootstrap.js'
import { MarkerCorruptError } from './bootstrap/marker.js'
import { NotificationService, HttpNotifier } from './services/notifications/index.js'
import { realtimeService } from './services/realtime.service.js'
import { startBackupScheduler } from './services/backup-scheduler.service.js'
import { getRedisClient } from './services/redis-client.service.js'
import { logBase, traceFields } from './telemetry/log-correlation.js'
import { telemetryRoutes } from './routes/telemetry.routes.js'

// Singleton notification service — exported for controllers.
export const notificationService = new NotificationService()


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
      // Identity, and the two fields that let a line find its trace.
      //
      // `service` / `env` / `version` come from the SAME variables the trace SDK reads, so a line
      // cannot be filed under a service the traces do not know. They fall back to what this service
      // has always emitted when nothing is configured, so a deployment that wants no telemetry sees
      // no change at all.
      base: {
        service: 'jinbe',
        environment: env.NODE_ENV,
        ...logBase(),
      },
      // Evaluated per line: the active span is a property of the moment, not of the logger.
      mixin: traceFields,
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

  // SCIM 2.0 provisioning (IdP → jinbe), OUTSIDE the /api scope: no Kratos
  // cookie, no TokenReview — routes enforce their own bearer-token auth
  // (middleware/scim-auth.ts; /scim/v2 is on the require-auth bypass list).
  await fastify.register(scimRoutes, { prefix: '/scim/v2' })

  await fastify.register(
    async function (api) {
      await api.register(telemetryRoutes)
      await api.register(whoamiRoutes)
      await api.register(meRoutes, { prefix: '/me' })
      await api.register(clusterRoutes, { prefix: '/clusters' })
      await api.register(databaseRoutes, { prefix: '/databases' })
      await api.register(backupRoutes, { prefix: '/backups' })
      await api.register(backupItemRoutes, { prefix: '/backup-items' })
      await api.register(databaseAPIRoutes, { prefix: '/database-apis' })
      await api.register(adminRoutes, { prefix: '/admin' })
      await api.register(rbacOpalRoutes, { prefix: '/admin/rbac' })  // Public OPAL data endpoints (no auth)
      await api.register(rbacRoutes, { prefix: '/admin/rbac' })      // Admin RBAC management (auth required)
      await api.register(rbacBundleRoutes, { prefix: '/admin/rbac' }) // Bundle export/import (super_admin)
      await api.register(authConfigRoutes, { prefix: '/admin/auth' }) // Kratos auth-method toggles (super_admin)
      await api.register(auditRoutes, { prefix: '/admin/audit' })
      await api.register(recertRoutes, { prefix: '/admin/recert' }) // Access recertification campaigns (admin; inbox/decision self-gated)
      await api.register(webhookRoutes, { prefix: '/webhooks' })  // Kratos after-hooks (self-authenticated)
      // Answers about a named subject rather than about its caller, so it takes a machine
      // credential and nothing else — its own hook, registered inside the plugin.
      await api.register(directoryRoutes, { prefix: '/directory' })
      await api.register(opaPolicyBundleRoutes, { prefix: '/opa' })
      await api.register(organizationUserRoutes, { prefix: '/organizations/:organizationId' })
      await api.register(apiKeyRoutes, { prefix: '/organizations/:organizationId' })
      await api.register(apiKeyInternalRoutes, { prefix: '/internal' }) // no-auth, cluster-internal only
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

      // Start notification service (Redis-backed outbox → notifiers).
      // Use a DEDICATED connection (.duplicate()): the consumer loop runs a
      // blocking `XREADGROUP … BLOCK 5000`, and ioredis serialises commands per
      // connection — on the shared singleton that block stalls every other
      // redis command (RBAC reads, /health ping) behind it for up to 5s per
      // cycle. realtimeService already isolates its blocking read the same way.
      if (env.JINBE_SERVICE_URL) {
        notificationService.setRedis(getRedisClient().duplicate())
        notificationService.register(new HttpNotifier({ url: env.JINBE_SERVICE_URL }))
        await notificationService.start()
      }

      // Real-time SSE fan-out — pushes a minimal change signal to connected
      // admin browsers (via Redis pub/sub, so it works across replicas).
      realtimeService.init(getRedisClient())

      // Push a full datasource refresh to opal-server. Defends against the
      // race where opal-server booted first, hit a 503 from us, and ended
      // up with an empty OPA dataset. Non-fatal — opal-server may also be
      // unreachable here, in which case the next admin mutation re-pushes.

      // Scheduled RBAC-bundle backup, run by jinbe itself (self-authenticated +
      // holds S3 creds). No-op unless backup is enabled. Replaces the external
      // aws-cli CronJob, which had no way to authenticate to /bundle/export.
      startBackupScheduler(fastify.log)
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
      notificationService.stop()
      realtimeService.stop()
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
