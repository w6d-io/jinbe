import { FastifyInstance } from 'fastify'
import { clusterController } from '../controllers/cluster.controller.js'
import { databaseController } from '../controllers/database.controller.js'
import { backupController } from '../controllers/backup.controller.js'
import { remapParam } from '../utils/route-helpers.js'
import {
  clusterCreateSchema,
  clusterUpdateSchema,
  clusterQuerySchema,
  clusterIdParamSchema,
} from '../schemas/cluster.schema.js'
import { databaseCreateSchema } from '../schemas/database.schema.js'
import { backupCreateSchema } from '../schemas/backup.schema.js'
import {
  clusterItemSchema,
  clusterBaseSchema,
  databaseBaseSchema,
  backupBaseSchema,
  notFoundResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'
import { zodToJsonSchema } from 'zod-to-json-schema'
import { getPaginatedResponseSchema } from '../utils/pagination.js'

// Shared verify response schema (used by both /verify and /:id/verify)
const verifyResponseSchema = {
  type: 'object',
  properties: {
    success: { type: 'boolean' },
    cluster: {
      type: 'object',
      nullable: true,
      properties: {
        name: { type: 'string' },
        server: { type: 'string' },
        version: { type: 'string' },
      },
    },
    user: {
      type: 'object',
      nullable: true,
      properties: {
        name: { type: 'string' },
        authMethod: {
          type: 'string',
          enum: ['token', 'client-certificate', 'exec', 'auth-provider', 'unknown'],
        },
      },
    },
    identity: {
      type: 'object',
      nullable: true,
      properties: {
        username: { type: 'string' },
        groups: { type: 'array', items: { type: 'string' } },
        uid: { type: 'string' },
      },
    },
    permissions: {
      type: 'object',
      nullable: true,
      properties: {
        canListNamespaces: { type: 'boolean' },
        canListPods: { type: 'boolean' },
        canCreateJobs: { type: 'boolean' },
        canListSecrets: { type: 'boolean' },
        namespaces: { type: 'array', items: { type: 'string' } },
      },
    },
    error: { type: 'string' },
  },
}

/**
 * Cluster routes
 * GET /clusters - Get all clusters
 * GET /clusters/:id - Get cluster by ID
 * POST /clusters - Create new cluster
 * POST /clusters/:id/databases - Create database under cluster
 * POST /clusters/:id/backups - Create backup under cluster
 * PUT /clusters/:id - Update cluster by ID
 * DELETE /clusters/:id - Delete cluster by ID
 */
export async function clusterRoutes(fastify: FastifyInstance) {
  // Get all clusters
  fastify.get(
    '/',
    {
      schema: {
        description: 'Get all clusters with optional pagination',
        tags: ['clusters'],
        querystring: zodToJsonSchema(clusterQuerySchema),
        response: {
          200: {
            oneOf: [
              {
                type: 'array',
                items: clusterItemSchema,
                description: 'Array response (when pagination not requested)',
              },
              {
                ...getPaginatedResponseSchema(clusterItemSchema),
                description: 'Paginated response (when page/pageSize provided)',
              },
            ],
          },
          401: unauthorizedResponseSchema,
        },
      },
    },
    clusterController.getClusters.bind(clusterController)
  )

  // Get cluster by ID
  fastify.get(
    '/:id',
    {
      schema: {
        description: 'Get cluster by ID',
        tags: ['clusters'],
        params: zodToJsonSchema(clusterIdParamSchema),
        querystring: zodToJsonSchema(clusterQuerySchema),
        response: {
          200: clusterItemSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    clusterController.getClusterById.bind(clusterController)
  )

  // Create new cluster
  fastify.post(
    '/',
    {
      schema: {
        description: 'Create new cluster',
        tags: ['clusters'],
        body: zodToJsonSchema(clusterCreateSchema),
        response: {
          201: clusterBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    clusterController.createCluster.bind(clusterController)
  )

  // Create new database under cluster
  fastify.post(
    '/:id/databases',
    {
      schema: {
        description: 'Create new database under a specific cluster',
        tags: ['databases'],
        params: zodToJsonSchema(clusterIdParamSchema),
        body: zodToJsonSchema(databaseCreateSchema),
        response: {
          201: databaseBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    remapParam('id', 'clusterId', databaseController.createDatabase.bind(databaseController))
  )

  // Create new backup under cluster
  fastify.post(
    '/:id/backups',
    {
      schema: {
        description: 'Create new backup under a specific cluster',
        tags: ['backups'],
        params: zodToJsonSchema(clusterIdParamSchema),
        body: zodToJsonSchema(backupCreateSchema),
        response: {
          201: backupBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    remapParam('id', 'clusterId', backupController.createBackup.bind(backupController))
  )

  // Update cluster by ID
  fastify.put(
    '/:id',
    {
      schema: {
        description: 'Update cluster by ID',
        tags: ['clusters'],
        params: zodToJsonSchema(clusterIdParamSchema),
        body: zodToJsonSchema(clusterUpdateSchema),
        response: {
          200: clusterBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    clusterController.updateCluster.bind(clusterController)
  )

  // Delete cluster by ID
  fastify.delete(
    '/:id',
    {
      schema: {
        description: 'Delete cluster by ID',
        tags: ['clusters'],
        params: zodToJsonSchema(clusterIdParamSchema),
        response: {
          200: clusterBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    clusterController.deleteCluster.bind(clusterController)
  )

  // Verify kubeconfig (standalone, before creating cluster)
  fastify.post(
    '/verify',
    {
      schema: {
        description:
          'Verify a kubeconfig and retrieve token identity/permissions. Use this before creating a cluster to validate the configuration.',
        tags: ['clusters'],
        body: {
          type: 'object',
          required: ['config'],
          properties: {
            config: {
              type: 'string',
              description: 'The kubeconfig YAML content to verify',
            },
          },
        },
        response: {
          200: verifyResponseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    clusterController.verifyKubeconfig.bind(clusterController)
  )

  // Verify existing cluster's kubeconfig
  fastify.post(
    '/:id/verify',
    {
      schema: {
        description:
          'Verify the kubeconfig of an existing cluster and retrieve token identity/permissions',
        tags: ['clusters'],
        params: zodToJsonSchema(clusterIdParamSchema),
        response: {
          200: verifyResponseSchema,
          400: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              error: { type: 'string' },
            },
          },
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    clusterController.verifyClusterConfig.bind(clusterController)
  )
}
