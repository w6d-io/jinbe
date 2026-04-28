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
import { testDatabaseConnection, applyMongoValidation } from './utils/prisma.js'
import type { OathkeeperRule } from './services/redis-rbac.repository.js'

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
      const { redisRbacRepository } = await import('./services/redis-rbac.repository.js')
      const groups = await redisRbacRepository.getGroups()
      if (Object.keys(groups).length === 0) {
        fastify.log.info('Redis empty — seeding default RBAC configuration...')
        await redisRbacRepository.setGroup('super_admins', { global: ['super_admin'] })
        await redisRbacRepository.setGroup('admins', { jinbe: ['admin'] })
        await redisRbacRepository.setGroup('devs', { jinbe: ['editor'] })
        await redisRbacRepository.setGroup('viewers', { jinbe: ['viewer'] })
        await redisRbacRepository.setGroup('users', {})
        await redisRbacRepository.setRoles('global', { super_admin: ['*'] })
        await redisRbacRepository.setRoles('jinbe', {
          admin: ['*'],
          operator: ['clusters:list', 'clusters:read', 'clusters:create', 'clusters:update', 'clusters:delete', 'databases:list', 'databases:read', 'databases:create', 'databases:update', 'databases:delete'],
          editor: ['databases:list', 'databases:read', 'databases:create', 'databases:update', 'databases:delete'],
          viewer: ['databases:list', 'databases:read'],
        })
        await redisRbacRepository.addService('jinbe')
        await redisRbacRepository.addService('global')

        // Rego policy is managed by OPAL (pulled from git policy repo)
        // Jinbe only seeds RBAC data (groups, roles, rules), not policy

        await redisRbacRepository.invalidateBundleEtag()
        fastify.log.info('Default RBAC data seeded successfully (groups, roles, access rules)')
      } else {
        fastify.log.info(`Redis has ${Object.keys(groups).length} groups — skipping RBAC seed`)
      }

      // Access rules always reseeded on startup — domain-aware, idempotent
      {
        const kratosPublic = env.KRATOS_PUBLIC_URL || 'http://kratos-public:80'
        const jinbeInternal = env.JINBE_INTERNAL_URL || 'http://jinbe:8080'
        const authDomain = env.AUTH_DOMAIN
        const appDomain = env.APP_DOMAIN
        const apiDomain = env.API_DOMAIN || appDomain
        const loginUiUrl = kratosPublic.replace(/kratos-public(:\d+)?$/, 'kratos-login-ui:80')
        const adminUiUrl = jinbeInternal.replace(/jinbe(:\d+)?$/, 'admin-ui:80')
        const rules: OathkeeperRule[] = []
        const esc = (d: string) => d.replace(/\./g, '\\.')

        const kratosMatch = authDomain
          ? `<https?://${esc(authDomain)}/(self-service|sessions|schemas|\\.well-known)(/.*)?$>`
          : '<https?://[^/]+/(self-service|sessions|schemas|\\.well-known)(/.*)?$>'
        rules.push({
          id: 'kratos-public',
          upstream: { url: kratosPublic },
          match: { url: kratosMatch, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] },
          authenticators: [{ handler: 'noop' }],
          authorizer: { handler: 'allow' },
          mutators: [{ handler: 'noop' }],
        })

        if (authDomain) {
          rules.push({
            id: 'auth-all',
            upstream: { url: loginUiUrl, preserve_host: true },
            match: { url: `<https?://${esc(authDomain)}/(?!self-service|sessions|schemas|\\.well-known).*>`, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] },
            authenticators: [{ handler: 'noop' }],
            authorizer: { handler: 'allow' },
            mutators: [{ handler: 'noop' }],
          })
        }

        const apiDomains = [apiDomain, appDomain].filter(Boolean).map(d => esc(d!))
        const apiMatch = apiDomains.length > 0
          ? `<https?://(${apiDomains.join('|')})/api/.*>`
          : '<https?://[^/]+/api/.*>'
        rules.push({
          id: 'api-cors',
          upstream: { url: jinbeInternal },
          match: { url: apiMatch, methods: ['OPTIONS'] },
          authenticators: [{ handler: 'noop' }],
          authorizer: { handler: 'allow' },
          mutators: [{ handler: 'noop' }],
        })
        if (apiDomain) {
          rules.push({
            id: 'jinbe-preflight',
            upstream: { url: `http://auth-w6d-jinbe:8080`, preserve_host: false },
            match: {
              url: `<https://jinbe.${esc(apiDomain)}/<.*>>`,
              methods: ['OPTIONS'],
            },
            authenticators: [{ handler: 'noop' }],
            authorizer: { handler: 'allow' },
            mutators: [{ handler: 'noop' }],
          })
        }
        rules.push({
          id: 'jinbe',
          upstream: { url: jinbeInternal },
          match: { url: apiMatch, methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] },
          authenticators: [{ handler: 'cookie_session' }],
          authorizer: { handler: 'remote_json' },
          mutators: [{ handler: 'header' }],
        })

        if (appDomain) {
          rules.push({
            id: 'kuma',
            upstream: { url: adminUiUrl },
            match: { url: `<https?://${esc(appDomain)}/(?!api/).*>`, methods: ['GET', 'POST', 'OPTIONS'] },
            authenticators: [{ handler: 'cookie_session' }],
            authorizer: { handler: 'allow' },
            mutators: [{ handler: 'noop' }],
          })
        }

        await redisRbacRepository.setAccessRules(rules)
        fastify.log.info({ ruleCount: rules.length, authDomain, appDomain }, 'Access rules synced to Redis')
      }

      // Ensure jinbe's own route_map is current — runs every startup (idempotent)
      const jinbeRouteMap = await redisRbacRepository.getRouteMap('jinbe')
      if (!jinbeRouteMap || jinbeRouteMap.rules.length <= 1) {
        await redisRbacRepository.setRouteMap('jinbe', { rules: [
          { method: 'GET',    path: '/api/health' },
          { method: 'GET',    path: '/api/whoami' },
          { method: 'GET',    path: '/docs/:any*' },
          { method: 'GET',    path: '/api/clusters',                        permission: 'clusters:list' },
          { method: 'POST',   path: '/api/clusters',                        permission: 'clusters:create' },
          { method: 'GET',    path: '/api/clusters/:id',                    permission: 'clusters:read' },
          { method: 'PUT',    path: '/api/clusters/:id',                    permission: 'clusters:update' },
          { method: 'DELETE', path: '/api/clusters/:id',                    permission: 'clusters:delete' },
          { method: 'POST',   path: '/api/clusters/verify',                 permission: 'clusters:create' },
          { method: 'POST',   path: '/api/clusters/:id/verify',             permission: 'clusters:update' },
          { method: 'POST',   path: '/api/clusters/:id/databases',          permission: 'databases:create' },
          { method: 'POST',   path: '/api/clusters/:id/backups',            permission: 'backups:create' },
          { method: 'POST',   path: '/api/clusters/:clusterId/jobs',        permission: 'jobs:create' },
          { method: 'GET',    path: '/api/clusters/:clusterId/jobs',        permission: 'jobs:list' },
          { method: 'GET',    path: '/api/clusters/:clusterId/jobs/pods',   permission: 'jobs:read' },
          { method: 'GET',    path: '/api/databases',                       permission: 'databases:list' },
          { method: 'GET',    path: '/api/databases/:id',                   permission: 'databases:read' },
          { method: 'GET',    path: '/api/databases/:id/list',              permission: 'databases:read' },
          { method: 'PUT',    path: '/api/databases/:id',                   permission: 'databases:update' },
          { method: 'DELETE', path: '/api/databases/:id',                   permission: 'databases:delete' },
          { method: 'GET',    path: '/api/databases/:id/api',               permission: 'databases:read' },
          { method: 'POST',   path: '/api/databases/:id/api',               permission: 'databases:create' },
          { method: 'GET',    path: '/api/backups',                         permission: 'backups:list' },
          { method: 'GET',    path: '/api/backups/:id',                     permission: 'backups:read' },
          { method: 'DELETE', path: '/api/backups/:id',                     permission: 'backups:delete' },
          { method: 'POST',   path: '/api/backups/:id/items',               permission: 'backups:create' },
          { method: 'GET',    path: '/api/backup-items',                    permission: 'backups:list' },
          { method: 'GET',    path: '/api/backup-items/:id',                permission: 'backups:read' },
          { method: 'PUT',    path: '/api/backup-items/:id',                permission: 'backups:update' },
          { method: 'DELETE', path: '/api/backup-items/:id',                permission: 'backups:delete' },
          { method: 'GET',    path: '/api/database-apis',                   permission: 'databases:list' },
          { method: 'GET',    path: '/api/database-apis/:id',               permission: 'databases:read' },
          { method: 'PUT',    path: '/api/database-apis/:id',               permission: 'databases:update' },
          { method: 'DELETE', path: '/api/database-apis/:id',               permission: 'databases:delete' },
          { method: 'GET',    path: '/api/admin/rbac/users',                permission: 'admin:read' },
          { method: 'GET',    path: '/api/admin/rbac/groups',               permission: 'admin:read' },
          { method: 'POST',   path: '/api/admin/rbac/groups',               permission: 'admin:create' },
          { method: 'PUT',    path: '/api/admin/rbac/groups/:name',         permission: 'admin:update' },
          { method: 'DELETE', path: '/api/admin/rbac/groups/:name',         permission: 'admin:delete' },
          { method: 'GET',    path: '/api/admin/rbac/services',             permission: 'admin:read' },
          { method: 'POST',   path: '/api/admin/rbac/services',             permission: 'admin:create' },
          { method: 'DELETE', path: '/api/admin/rbac/services/:name',       permission: 'admin:delete' },
          { method: 'GET',    path: '/api/admin/rbac/services/:name/roles', permission: 'admin:read' },
          { method: 'PUT',    path: '/api/admin/rbac/services/:name/routes',permission: 'admin:update' },
          { method: 'GET',    path: '/api/admin/rbac/access-rules',         permission: 'admin:read' },
          { method: 'GET',    path: '/api/admin/rbac/access-rules/:id',     permission: 'admin:read' },
          { method: 'POST',   path: '/api/admin/rbac/access-rules',         permission: 'admin:create' },
          { method: 'PUT',    path: '/api/admin/rbac/access-rules/:id',     permission: 'admin:update' },
          { method: 'DELETE', path: '/api/admin/rbac/access-rules/:id',     permission: 'admin:delete' },
          { method: 'POST',   path: '/api/admin/rbac/simulate',             permission: 'admin:read' },
          { method: 'GET',    path: '/api/admin/rbac/history',              permission: 'admin:read' },
          { method: 'GET',    path: '/api/admin/audit/:any*',               permission: 'admin:read' },
        ]})
        fastify.log.info('Jinbe route_map seeded in Redis')
      }

      // Seed kuma (admin dashboard) service + route_map if APP_DOMAIN is configured
      if (env.APP_DOMAIN) {
        const kumaExists = await redisRbacRepository.serviceExists('kuma')
        if (!kumaExists) {
          await redisRbacRepository.addService('kuma')
          await redisRbacRepository.setRoles('kuma', {
            admin: ['*'],
            viewer: ['read'],
          })
          // Propagate kuma roles to existing groups
          const groups = await redisRbacRepository.getGroups()
          if (groups['super_admins']) {
            groups['super_admins']['kuma'] = ['admin']
            await redisRbacRepository.setGroup('super_admins', groups['super_admins'])
          }
          if (groups['admins']) {
            groups['admins']['kuma'] = ['admin']
            await redisRbacRepository.setGroup('admins', groups['admins'])
          }
          if (groups['viewers']) {
            groups['viewers']['kuma'] = ['viewer']
            await redisRbacRepository.setGroup('viewers', groups['viewers'])
          }
          fastify.log.info('Kuma service seeded in Redis')
        }
        const kumaRouteMap = await redisRbacRepository.getRouteMap('kuma')
        if (!kumaRouteMap) {
          // Kuma is a pure frontend SPA — no own API backend.
          // All /api/... calls from kuma are proxied to jinbe and protected by jinbe's route_map.
          // Broad wildcards (/:any*) must NOT be here — they would make all jinbe routes "public".
          await redisRbacRepository.setRouteMap('kuma', { rules: [] })
          fastify.log.info('Kuma route_map seeded in Redis')
        }
      }

      // Create default admin user in Kratos if ADMIN_EMAIL is set (runs every startup, idempotent)
      const adminEmail = process.env.ADMIN_EMAIL
      const adminPassword = process.env.ADMIN_PASSWORD || 'changeme123!'
      const adminName = process.env.ADMIN_NAME || 'Admin'
      if (adminEmail) {
        try {
          const { kratosService } = await import('./services/kratos.service.js')
          const { identities } = await kratosService.listIdentities(1, undefined, adminEmail)
          if (identities.length === 0) {
            const identity = await kratosService.createIdentity({
              schema_id: 'default',
              state: 'active',
              traits: { email: adminEmail, name: adminName },
              credentials: { password: { config: { password: adminPassword } } },
              metadata_admin: { groups: ['super_admins'] },
              verifiable_addresses: [{ value: adminEmail, verified: true, via: 'email', status: 'completed' }],
            })
            fastify.log.info({ email: adminEmail, id: identity.id }, 'Default admin user created')
          } else {
            fastify.log.debug({ email: adminEmail }, 'Admin user already exists')
          }
        } catch (err) {
          fastify.log.warn({ err, email: adminEmail }, 'Failed to create default admin user — Kratos may not be ready yet')
        }
      }
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
