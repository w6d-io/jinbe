import fp from 'fastify-plugin'
import swagger from '@fastify/swagger'
import swaggerUi from '@fastify/swagger-ui'
import { env } from '../config/index.js'
import { FastifyPluginAsync } from 'fastify'

/**
 * Swagger documentation plugin
 * Provides OpenAPI 3.1 documentation at /docs
 */
const swaggerPlugin: FastifyPluginAsync = fp(async (fastify) => {
  if (!env.ENABLE_SWAGGER && env.NODE_ENV === 'production') {
    fastify.log.info('Swagger disabled in production')
    return
  }

  await fastify.register(swagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'Jinbe API',
        description:
          'Jinbe API for Kubernetes cluster and database management.\n\n' +
          '## Authentication\n' +
          'Most endpoints require authentication via the `ory_kratos_session` cookie.\n' +
          'Use the **Authorize** button to set your session cookie value.\n\n' +
          'Public endpoints (no auth required):\n' +
          '- `GET /api/health`\n' +
          '- `GET /api/whoami`',
        version: '1.0.0',
        contact: {
          name: 'Jinbe Team',
        },
      },
      servers: [
        {
          url: env.BASE_URL || `http://localhost:${env.PORT}`,
          description: 'Local Development',
        },
        {
          url: 'https://jinbe.dev.w6d.io',
          description: 'Jinbe API - Development Environment',
        },
      ],
      tags: [
        { name: 'auth', description: 'Authentication and identity' },
        { name: 'admin', description: 'Admin user management (Kratos)' },
        { name: 'git-config', description: 'Git configuration file management (Admin only) - GitOps proxy for JSON config files' },
        { name: 'rbac', description: 'RBAC management (Admin only) - User bindings, groups, services, and Oathkeeper access rules' },
        { name: 'clusters', description: 'Kubernetes cluster management' },
        { name: 'databases', description: 'Database management' },
        { name: 'database-apis', description: 'Database API management' },
        { name: 'backups', description: 'Backup management' },
        { name: 'backup-items', description: 'Backup item management' },
        { name: 'health', description: 'Health check endpoint' },
      ],
      components: {
        securitySchemes: {
          kratosSession: {
            type: 'apiKey',
            in: 'cookie',
            name: 'ory_kratos_session',
            description: 'Ory Kratos session cookie. Get this from your browser after logging in.',
          },
        },
        schemas: {
          UnauthorizedError: {
            type: 'object',
            properties: {
              error: { type: 'string', example: 'Unauthorized' },
              message: {
                type: 'string',
                example:
                  'Valid authentication required. Please provide a valid ory_kratos_session cookie.',
              },
            },
          },
        },
      },
      // Apply security globally to all endpoints
      security: [{ kratosSession: [] }],
    },
  })

  await fastify.register(swaggerUi, {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'list',
      deepLinking: true,
      tryItOutEnabled: true,
      persistAuthorization: true, // Keep auth between page reloads
    },
  })

  fastify.log.info('Swagger plugin registered at /docs')
})

export default swaggerPlugin
