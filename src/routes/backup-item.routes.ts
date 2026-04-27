import { FastifyInstance } from 'fastify'
import { backupItemController } from '../controllers/backup-item.controller.js'
import {
  backupItemUpdateSchema,
  backupItemIdParamSchema,
} from '../schemas/backup-item.schema.js'
import {
  backupItemSchema,
  backupItemBaseSchema,
  notFoundResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'
import { zodToJsonSchema } from 'zod-to-json-schema'

/**
 * BackupItem routes
 * GET /backup-items - Get all backup items
 * GET /backup-items/:id - Get backup item by ID
 * PUT /backup-items/:id - Update backup item by ID
 * DELETE /backup-items/:id - Delete backup item by ID
 *
 * Note: POST is at /backups/:id/items (see backup.routes.ts)
 */
export async function backupItemRoutes(fastify: FastifyInstance) {
  // Get all backup items
  fastify.get(
    '/',
    {
      schema: {
        description: 'Get all backup items (optionally filtered by backupId)',
        tags: ['backup-items'],
        querystring: {
          type: 'object',
          properties: {
            backupId: { type: 'string' },
          },
        },
        response: {
          200: {
            type: 'array',
            items: backupItemSchema,
          },
          401: unauthorizedResponseSchema,
        },
      },
    },
    backupItemController.getBackupItems.bind(backupItemController)
  )

  // Get backup item by ID
  fastify.get(
    '/:id',
    {
      schema: {
        description: 'Get backup item by ID',
        tags: ['backup-items'],
        params: zodToJsonSchema(backupItemIdParamSchema),
        response: {
          200: backupItemSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    backupItemController.getBackupItemById.bind(backupItemController)
  )

  // Update backup item by ID
  fastify.put(
    '/:id',
    {
      schema: {
        description: 'Update backup item by ID',
        tags: ['backup-items'],
        params: zodToJsonSchema(backupItemIdParamSchema),
        body: zodToJsonSchema(backupItemUpdateSchema),
        response: {
          200: backupItemBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    backupItemController.updateBackupItem.bind(backupItemController)
  )

  // Delete backup item by ID
  fastify.delete(
    '/:id',
    {
      schema: {
        description: 'Delete backup item by ID',
        tags: ['backup-items'],
        params: zodToJsonSchema(backupItemIdParamSchema),
        response: {
          200: backupItemBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    backupItemController.deleteBackupItem.bind(backupItemController)
  )
}
