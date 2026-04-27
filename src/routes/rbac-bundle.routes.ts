import { FastifyInstance } from 'fastify'
import { requireSuperAdmin } from '../middleware/require-admin.js'
import { rbacBundleService, type AuthBundle } from '../services/rbac-bundle.service.js'

/**
 * Auth config bundle export / import routes.
 *
 * GET  /api/admin/rbac/bundle/export  — download full bundle as JSON
 * POST /api/admin/rbac/bundle/import  — restore bundle (upsert semantics)
 *
 * Both require super_admin. Internal cluster requests bypass the check.
 */
export async function rbacBundleRoutes(fastify: FastifyInstance) {
  // Export
  fastify.get(
    '/bundle/export',
    {
      preHandler: requireSuperAdmin,
      schema: {
        description: 'Export all RBAC config and identities as a portable JSON bundle.',
        tags: ['rbac', 'backup'],
        response: {
          200: { type: 'object', additionalProperties: true },
        },
      },
    },
    async (_request, reply) => {
      const bundle = await rbacBundleService.export()
      const filename = `auth-bundle-${bundle.exportedAt.slice(0, 10)}.json`
      reply.header('Content-Disposition', `attachment; filename="${filename}"`)
      reply.header('Content-Type', 'application/json')
      return bundle
    }
  )

  // Import
  fastify.post(
    '/bundle/import',
    {
      preHandler: requireSuperAdmin,
      schema: {
        description: 'Import an auth bundle — restores RBAC config and upserts identities.',
        tags: ['rbac', 'backup'],
        body: { type: 'object', additionalProperties: true },
        response: {
          200: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              imported: { type: 'object', additionalProperties: true },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const bundle = request.body as AuthBundle

      if (!bundle?.version || !bundle?.rbac) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Invalid bundle format — missing version or rbac fields.',
        })
      }
      if (bundle.version !== '1') {
        return reply.status(400).send({
          error: 'Bad Request',
          message: `Unsupported bundle version: ${bundle.version}`,
        })
      }

      const actor = {
        email: request.userContext?.email,
        ip: request.ip,
      }
      const result = await rbacBundleService.import(bundle, actor)

      return { success: true, imported: result }
    }
  )
}
