import { FastifyInstance } from 'fastify'
import { databaseController } from '../controllers/database.controller.js'
import { databaseAPIController } from '../controllers/database-api.controller.js'
import { remapParam } from '../utils/route-helpers.js'
import { databaseUpdateSchema } from '../schemas/database.schema.js'
import { databaseAPICreateSchema } from '../schemas/database-api.schema.js'
import {
  databaseItemSchema,
  databaseBaseSchema,
  databaseAPIItemSchema,
  databaseAPIBaseSchema,
  notFoundResponseSchema,
  unauthorizedResponseSchema,
  objectIdParamSchema,
} from '../schemas/response-schemas.js'
import { zodToJsonSchema } from 'zod-to-json-schema'
import { getPaginatedResponseSchema } from '../utils/pagination.js'

/**
 * Database routes
 * GET /databases - Get all databases
 * GET /databases/:id - Get database by ID
 * GET /databases/:id/list - List databases from the actual server (via db-agent or direct connection)
 * GET /databases/:id/api - Get database API config
 * POST /databases/:id/api - Create database API config
 * PUT /databases/:id - Update database by ID
 * DELETE /databases/:id - Delete database by ID
 *
 * Note: POST database is at /clusters/:id/databases (see cluster.routes.ts)
 */
export async function databaseRoutes(fastify: FastifyInstance) {
  // Get all databases
  fastify.get(
    '/',
    {
      schema: {
        description:
          'Get all databases (optionally filtered by clusterId, with pagination)',
        tags: ['databases'],
        querystring: {
          type: 'object',
          properties: {
            clusterId: { type: 'string', description: 'Filter by cluster ID' },
            page: {
              type: 'integer',
              minimum: 1,
              default: 1,
              description: 'Page number (starts at 1)',
            },
            pageSize: {
              type: 'integer',
              minimum: 1,
              maximum: 100,
              default: 10,
              description: 'Items per page (max 100)',
            },
          },
        },
        response: {
          200: {
            oneOf: [
              {
                type: 'array',
                items: databaseItemSchema,
                description: 'Array response (when pagination not requested)',
              },
              {
                ...getPaginatedResponseSchema(databaseItemSchema),
                description: 'Paginated response (when page/pageSize provided)',
              },
            ],
          },
          401: unauthorizedResponseSchema,
        },
      },
    },
    databaseController.getDatabases.bind(databaseController)
  )

  // Get database by ID
  fastify.get(
    '/:id',
    {
      schema: {
        description: 'Get database by ID',
        tags: ['databases'],
        params: zodToJsonSchema(objectIdParamSchema),
        response: {
          200: databaseItemSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    databaseController.getDatabaseById.bind(databaseController)
  )

  // List databases from the actual database server
  fastify.get(
    '/:id/list',
    {
      schema: {
        description: 'List all databases from the PostgreSQL/MongoDB server with their roles and sizes. Uses db-agent API if configured, otherwise connects directly.',
        tags: ['databases'],
        params: zodToJsonSchema(objectIdParamSchema),
        response: {
          200: {
            type: 'object',
            description: 'Map of database names to their roles and size',
            additionalProperties: {
              type: 'object',
              properties: {
                roles: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      username: { type: 'string' },
                      adminUsername: { type: 'string' },
                    },
                    required: ['username', 'adminUsername'],
                  },
                },
                size: { type: 'string' },
              },
              required: ['roles', 'size'],
            },
          },
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    databaseController.listDatabasesFromServer.bind(databaseController)
  )

  // Get database API config by database ID
  fastify.get(
    '/:id/api',
    {
      schema: {
        description: 'Get database API configuration for a specific database',
        tags: ['database-apis'],
        params: zodToJsonSchema(objectIdParamSchema),
        response: {
          200: databaseAPIItemSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    remapParam('id', 'databaseId', databaseAPIController.getDatabaseAPIByDatabaseId.bind(databaseAPIController))
  )

  // Create database API config under database
  fastify.post(
    '/:id/api',
    {
      schema: {
        description:
          'Create database API configuration for a specific database',
        tags: ['database-apis'],
        params: zodToJsonSchema(objectIdParamSchema),
        body: zodToJsonSchema(databaseAPICreateSchema),
        response: {
          201: databaseAPIBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    remapParam('id', 'databaseId', databaseAPIController.createDatabaseAPI.bind(databaseAPIController))
  )

  // Update database by ID
  fastify.put(
    '/:id',
    {
      schema: {
        description: 'Update database by ID',
        tags: ['databases'],
        params: zodToJsonSchema(objectIdParamSchema),
        body: zodToJsonSchema(databaseUpdateSchema),
        response: {
          200: databaseBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    databaseController.updateDatabase.bind(databaseController)
  )

  // Delete database by ID
  fastify.delete(
    '/:id',
    {
      schema: {
        description: 'Delete database by ID',
        tags: ['databases'],
        params: zodToJsonSchema(objectIdParamSchema),
        response: {
          200: databaseBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    databaseController.deleteDatabase.bind(databaseController)
  )
}
