import { FastifyInstance } from 'fastify'
import { backupController } from '../controllers/backup.controller.js'
import { backupItemController } from '../controllers/backup-item.controller.js'
import { remapParam } from '../utils/route-helpers.js'
import { backupIdParamSchema } from '../schemas/backup.schema.js'
import { backupItemCreateSchema } from '../schemas/backup-item.schema.js'
import {
  backupFullSchema,
  backupBaseSchema,
  backupItemBaseSchema,
  notFoundResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'
import { zodToJsonSchema } from 'zod-to-json-schema'

/**
 * Backup routes
 * GET /backups - Get all backups
 * GET /backups/:id - Get backup by ID
 * POST /backups/:id/items - Create backup item under backup
 * DELETE /backups/:id - Delete backup by ID
 *
 * Note: POST backup is at /clusters/:id/backups (see cluster.routes.ts)
 */
export async function backupRoutes(fastify: FastifyInstance) {
  // Get all backups
  fastify.get(
    '/',
    {
      schema: {
        description: 'Get all backups (optionally filtered by clusterId)',
        tags: ['backups'],
        querystring: {
          type: 'object',
          properties: {
            clusterId: { type: 'string' },
          },
        },
        response: {
          200: {
            type: 'array',
            items: backupFullSchema,
          },
          401: unauthorizedResponseSchema,
        },
      },
    },
    backupController.getBackups.bind(backupController)
  )

  // Get backup by ID
  fastify.get(
    '/:id',
    {
      schema: {
        description: 'Get backup by ID',
        tags: ['backups'],
        params: zodToJsonSchema(backupIdParamSchema),
        response: {
          200: backupFullSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    backupController.getBackupById.bind(backupController)
  )

  // Create new backup item under backup
  fastify.post(
    '/:id/items',
    {
      schema: {
        description: 'Create new backup item under a specific backup',
        tags: ['backup-items'],
        params: zodToJsonSchema(backupIdParamSchema),
        body: zodToJsonSchema(backupItemCreateSchema),
        response: {
          201: backupItemBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    remapParam('id', 'backupId', backupItemController.createBackupItem.bind(backupItemController))
  )

  // Delete backup by ID
  fastify.delete(
    '/:id',
    {
      schema: {
        description: 'Delete backup by ID',
        tags: ['backups'],
        params: zodToJsonSchema(backupIdParamSchema),
        response: {
          200: backupBaseSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    backupController.deleteBackup.bind(backupController)
  )
}
