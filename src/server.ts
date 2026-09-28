import Fastify from 'fastify'
import { env } from './config/index.js'
import { errorHandler } from './middleware/error-handler.js'
import { requestIdMiddleware } from './middleware/request-id.js'
import { extractIdentity } from './middleware/identity-extractor.js'
import { requireAuth } from './middleware/require-auth.js'
import { requestLogger } from './middleware/request-logger.js'

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
import { userManagementRoutes } from './routes/user-management.routes.js'
import { jobRoutes } from './routes/job.routes.js'
import { rbacRoutes } from './routes/rbac.routes.js'
import { orgGrantsRoutes } from './routes/org-grants.routes.js'
import { rbacOpalRoutes } from './routes/rbac-opal.routes.js'
import { publicSitesRoutes } from './sites/public.routes.js'
import { startSitesBackground } from './sites/sync.js'
import { startAccessRollup } from './audit/gateway/rollup.js'
import { secondFactorPublicRoutes, secondFactorSettingsRoutes } from './second-factor/routes.js'
import { requireSecondFactor } from './second-factor/gate.js'
import { rbacBundleRoutes } from './routes/rbac-bundle.routes.js'
import { authConfigRoutes } from './routes/auth-config.routes.js'
import { opaBundleRoutes } from './routes/opa-bundle.routes.js'
import { oathkeeperRoutes } from './routes/oathkeeper.routes.js'
import { auditRoutes } from './routes/audit.routes.js'
import { auditApiRoutes } from './routes/audit-api.routes.js'
import { observabilityRoutes } from './routes/observability.routes.js'
import { webhookRoutes } from './routes/webhook.routes.js'
import { signInProtectionPublicRoutes, signInProtectionSettingsRoutes } from './sign-in-protection/routes.js'
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
import { opalPublisher } from './services/opal-publisher.js'
import { startBackupScheduler } from './services/backup-scheduler.service.js'
import { getRedisClient } from './services/redis-client.service.js'
import { rootLogger, componentLogger, captureProcessWarnings, fastifyLoggingOptions } from './telemetry/logger.js'
import { startMetricsServer } from './telemetry/metrics-server.js'
import { telemetryRoutes } from './routes/telemetry.routes.js'
import { isPublicRoute } from './middleware/require-auth.js'
import { recordRoute } from './policy/declared-routes.js'
import { auditRouteWrite } from './audit/route-events.js'
import { isBootstrapReady, markBootstrapReady } from './bootstrap/ready-state.js'
import { homeRoutes } from './home/routes.js'
import { startHomeBackground } from './home/jobs.js'

// Singleton notification service — exported for controllers.
export const notificationService = new NotificationService()


// Set after waitForBootstrap resolves (bootstrap/ready-state.ts). Health endpoint returns 503
// until then so the Deployment startupProbe absorbs the wait window.

/**
 * Build Fastify server instance
 */
export async function buildServer() {
  const fastify = Fastify({
    // JSON lines with redaction, ISO time and `log_type` — see telemetry/logger.ts.
    loggerInstance: rootLogger(),
    ...fastifyLoggingOptions,
    trustProxy: true,
  })

  // Set error handler
  fastify.setErrorHandler(errorHandler)

  // CORS must be registered FIRST to ensure headers are added even on 401 errors
  await fastify.register(corsPlugin)

  // Add request ID to all requests
  fastify.addHook('onRequest', requestIdMiddleware)

  // The published route table, collected as Fastify registers each route. Read off the guards that
  // were actually attached, so a row and the refusal behind it cannot disagree — and a route added
  // without a guard is absent from the table rather than described as open.
  fastify.addHook('onRoute', (route) => {
    recordRoute(route.method, route.url, [route.preHandler, route.onRequest], isPublicRoute)
  })

  // Extract user identity from Kratos session or proxy headers
  fastify.addHook('onRequest', extractIdentity)

  // Require authentication for all routes except public ones (health, whoami)
  fastify.addHook('onRequest', requireAuth)

  // Mandatory 2FA, server side: a session the policy says needs_2fa for this route is refused (422
  // second_factor_required) before any route gate runs — second-factor/gate.ts.
  fastify.addHook('onRequest', requireSecondFactor)

  // Register other plugins
  await fastify.register(rateLimitPlugin)
  await fastify.register(swaggerPlugin)

  // Register helmet after swagger to avoid CSP issues
  await fastify.register(helmetPlugin)

  // One request line per response + HTTP RED counters (after routes)
  fastify.addHook('onResponse', requestLogger)

  // One audit/v1 event per successful write whose route-table row says the route emits it (the
  // infrastructure CRUD, which has no emit downstream) — audit/route-events.ts, CONTROL AU-2.
  fastify.addHook('onSend', auditRouteWrite)

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
      const bootstrapReady = isBootstrapReady()
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
      await api.register(userManagementRoutes, { prefix: '/admin' }) // users/sessions, one permission per action
      await api.register(adminRoutes, { prefix: '/admin' })
      await api.register(rbacOpalRoutes, { prefix: '/admin/rbac' })  // OPAL data endpoints (OPAL client token)
      await api.register(rbacRoutes, { prefix: '/admin/rbac' })      // Admin RBAC management (auth required)
      await api.register(rbacBundleRoutes, { prefix: '/admin/rbac' }) // Bundle export/import (super_admin)
      await api.register(authConfigRoutes, { prefix: '/admin/auth' }) // Kratos auth-method toggles (super_admin)
      await api.register(secondFactorSettingsRoutes, { prefix: '/admin/settings' }) // groups that must use 2FA
      await api.register(signInProtectionSettingsRoutes, { prefix: '/admin/settings' }) // bot check + sign-up policy
      await api.register(auditRoutes, { prefix: '/admin/audit' })           // legacy Redis trail, until AUD-14
      await api.register(auditApiRoutes, { prefix: '/audit' })              // audit/v1 from Loki, scoped (AUD-9)
      await api.register(observabilityRoutes, { prefix: '/admin/observability' }) // ops logs / trace / links (OBS-4.1)
      await api.register(homeRoutes, { prefix: '/home' }) // briefing, own scope guard — NOT under /admin (requireAdmin would lock out support and org admins)
      await api.register(recertRoutes, { prefix: '/admin/recert' }) // Access recertification campaigns (admin; inbox/decision self-gated)
      await api.register(webhookRoutes, { prefix: '/webhooks' })  // Kratos after-hooks (self-authenticated)
      // Answers about a named subject rather than about its caller, so it takes a machine
      // credential and nothing else — its own hook, registered inside the plugin.
      await api.register(directoryRoutes, { prefix: '/directory' })
      await api.register(opaPolicyBundleRoutes, { prefix: '/opa' })
      await api.register(organizationUserRoutes, { prefix: '/organizations/:organizationId' })
      await api.register(orgGrantsRoutes, { prefix: '/organizations/:organizationId' }) // org admin; OPA can_grant
      await api.register(apiKeyRoutes, { prefix: '/organizations/:organizationId' })
      await api.register(apiKeyInternalRoutes, { prefix: '/internal' }) // no-auth, cluster-internal only
      await api.register(opaBundleRoutes, { prefix: '/opa' })
      await api.register(oathkeeperRoutes, { prefix: '/oathkeeper' })
      await api.register(publicSitesRoutes, { prefix: '/public/sites' }) // login-ui: branding, logo, access-reason
      await api.register(secondFactorPublicRoutes, { prefix: '/public/second-factor' }) // login-ui: must this visitor enrol/step up?
      await api.register(signInProtectionPublicRoutes, { prefix: '/public/sign-in-protection' }) // login-ui: widget + sign-up mode; gateway bot check
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
      componentLogger('startup').info('DATABASE_URL not set — MongoDB features disabled (clusters, backups)')
    }

    const fastify = await buildServer()

    // Listen first so startupProbe can hit /api/health (which returns 503 until ready).
    await fastify.listen({
      port: env.PORT,
      host: env.HOST,
    })
    fastify.log.info(`Server listening on http://${env.HOST}:${env.PORT}`)
    // Prometheus on its own port, never through the app port Oathkeeper fronts.
    startMetricsServer(fastify.log)
    if (env.ENABLE_SWAGGER) {
      fastify.log.info(`API docs available at http://${env.HOST}:${env.PORT}/docs`)
    }

    // Block until the bootstrap Job has written the marker. Default budget
    // 6 minutes — matches the chart's startupProbe (failureThreshold: 72,
    // periodSeconds: 5).
    try {
      const marker = await waitForBootstrap({ logger: fastify.log })
      markBootstrapReady()
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
      // unreachable here, in which case the push retries, then the manifest's periodic refresh
      // catches up. No-op without OPAL_SERVER_URL.
      void opalPublisher.refreshAll('jinbe-startup')

      // Scheduled RBAC-bundle backup, run by jinbe itself (self-authenticated +
      // holds S3 creds). No-op unless backup is enabled. Replaces the external
      // aws-cli CronJob, which had no way to authenticate to /bundle/export.
      startBackupScheduler(fastify.log)

      // Sites: re-create missing/drifted Site CRs from the intent, tick the migration dual run.
      startSitesBackground(fastify.log)

      // Audit: gateway decisions into the trail, one event per subject and host per hour.
      startAccessRollup(fastify.log)

      // Home: keeps the platform-scope briefing warm (leader only, Redis lock).
      startHomeBackground(fastify.log)
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
    componentLogger('startup').fatal({ err }, 'Failed to start server')
    process.exit(1)
  }
}

// Handle graceful shutdown
const signals = ['SIGINT', 'SIGTERM']
signals.forEach((signal) => {
  process.on(signal, async () => {
    componentLogger('shutdown').info({ signal }, 'Shutting down gracefully')
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
  // Before Fastify is built: it reports deprecations while constructing.
  captureProcessWarnings()
  start()
}
