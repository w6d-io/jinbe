import { FastifyInstance } from 'fastify'
import { databaseAPIController } from '../controllers/database-api.controller.js'
import {
  databaseAPIUpdateSchema,
  databaseAPIIdParamSchema,
} from '../schemas/database-api.schema.js'
import {
  databaseAPIItemSchema,
  databaseAPIBaseSchema,
  notFoundResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'
import { zodToJsonSchema } from 'zod-to-json-schema'

/**
 * DatabaseAPI routes
 * GET /database-apis - Get all database APIs
 * GET /database-apis/:id - Get database API by ID
 * PUT /database-apis/:id - Update database API by ID
 * DELETE /database-apis/:id - Delete database API by ID
 *
 * Note: GET/POST by databaseId are at /databases/:id/api (see database.routes.ts)
 */
export async function databaseAPIRoutes(fastify: FastifyInstance) {
  // Get all database APIs
  fastify.get(
    '/',
    {
      schema: {
        description: 'Get all database APIs',
        tags: ['database-apis'],
        response: {
          200: {
            type: 'array',
            items: databaseAPIItemSchema,
          },
          401: unauthorizedResponseSchema,
        },
      },
    },
    databaseAPIController.getDatabaseAPIs.bind(databaseAPIController)
  )

  // Get database API by ID
  fastify.get(
    '/:id',
    {
      schema: {
        description: 'Get database API by ID',
        tags: ['database-apis'],
        params: zodToJsonSchema(databaseAPIIdParamSchema),
        response: {
          200: databaseAPIItemSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    databaseAPIController.getDatabaseAPIById.bind(databaseAPIController)
  )

  // Update database API by ID
  fastify.put(
    '/:id',
    {
      schema: {
        description: 'Update database API by ID',
        tags: ['database-apis'],
        params: zodToJsonSchema(databaseAPIIdParamSchema),
        body: zodToJsonSchema(databaseAPIUpdateSchema),
        response: {
          200: databaseAPIBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    databaseAPIController.updateDatabaseAPI.bind(databaseAPIController)
  )

  // Delete database API by ID
  fastify.delete(
    '/:id',
    {
      schema: {
        description: 'Delete database API by ID',
        tags: ['database-apis'],
        params: zodToJsonSchema(databaseAPIIdParamSchema),
        response: {
          200: databaseAPIBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    databaseAPIController.deleteDatabaseAPI.bind(databaseAPIController)
  )
}
