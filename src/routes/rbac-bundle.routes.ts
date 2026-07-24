import { FastifyInstance } from 'fastify'
import { requireSuperAdmin } from '../middleware/require-admin.js'
import { rbacBundleService, type AuthBundle, ALL_BUNDLE_SECTIONS, type BundleSection } from '../services/rbac-bundle.service.js'
import { backupStore } from '../services/backup-store.service.js'

/**
 * Auth config bundle export / import + S3 backup routes.
 *
 * GET  /api/admin/rbac/bundle/export           — download bundle (optionally ?sections=)
 * POST /api/admin/rbac/bundle/import           — restore from an uploaded bundle (full replace)
 * GET  /api/admin/rbac/bundle/backups          — list S3 backup snapshots
 * POST /api/admin/rbac/bundle/backups/restore  — restore from an S3 snapshot key
 * POST /api/admin/rbac/bundle/backups/now      — export current config and upload to S3
 *
 * All require super_admin. Internal cluster requests bypass the check (the
 * backup CronJob uses the internal Host header).
 */
export async function rbacBundleRoutes(fastify: FastifyInstance) {
  const disabled = (reply: import('fastify').FastifyReply) =>
    reply.status(501).send({ error: 'Not Implemented', code: 'backup_disabled', message: 'S3 backup is not enabled on this deployment.' })

  // ── Export (optionally a subset of sections) ──
  fastify.get(
    '/bundle/export',
    {
      preHandler: requireSuperAdmin,
      schema: {
        description: 'Export RBAC config as a portable JSON bundle. ?sections=services,groups,… narrows it; omitted = full 1:1 snapshot.',
        tags: ['rbac', 'backup'],
        querystring: { type: 'object', properties: { sections: { type: 'string' } } },
        response: { 200: { type: 'object', additionalProperties: true } },
      },
    },
    async (request, reply) => {
      const raw = (request.query as { sections?: string })?.sections
      const sections = raw
        ? raw.split(',').map((s) => s.trim()).filter((s): s is BundleSection => (ALL_BUNDLE_SECTIONS as string[]).includes(s))
        : undefined
      const bundle = await rbacBundleService.export(sections)
      const filename = `auth-bundle-${bundle.exportedAt.slice(0, 10)}.json`
      reply.header('Content-Disposition', `attachment; filename="${filename}"`)
      reply.header('Content-Type', 'application/json')
      return bundle
    }
  )

  // ── Import (restore) from an uploaded bundle ──
  fastify.post(
    '/bundle/import',
    {
      preHandler: requireSuperAdmin,
      schema: {
        description: 'Import an auth bundle — restores RBAC config (full replace). Requires a full snapshot.',
        tags: ['rbac', 'backup'],
        body: { type: 'object', additionalProperties: true },
        response: {
          200: { type: 'object', properties: { success: { type: 'boolean' }, imported: { type: 'object', additionalProperties: true } } },
        },
      },
    },
    async (request, reply) => {
      const bundle = request.body as AuthBundle
      const err = validateFullBundle(bundle)
      if (err) return reply.status(400).send({ error: 'Bad Request', message: err })

      const actor = { email: request.userContext?.email, ip: request.ip }
      const result = await rbacBundleService.import(bundle, actor)
      return { success: true, imported: result }
    }
  )

  // ── List S3 backup snapshots ──
  fastify.get(
    '/bundle/backups',
    { preHandler: requireSuperAdmin, schema: { description: 'List RBAC bundle backups in S3.', tags: ['rbac', 'backup'] } },
    async (_request, reply) => {
      if (!backupStore.enabled()) return disabled(reply)
      const backups = await backupStore.listBackups()
      return { ...backupStore.config(), backups }
    }
  )

  // ── Restore from an S3 snapshot key ──
  fastify.post(
    '/bundle/backups/restore',
    {
      preHandler: requireSuperAdmin,
      schema: {
        description: 'Restore RBAC config from an S3 backup snapshot (full replace).',
        tags: ['rbac', 'backup'],
        body: { type: 'object', required: ['key'], properties: { key: { type: 'string' } } },
      },
    },
    async (request, reply) => {
      if (!backupStore.enabled()) return disabled(reply)
      const { key } = request.body as { key?: string }
      if (!key) return reply.status(400).send({ error: 'Bad Request', message: 'key is required' })

      const bundle = await backupStore.getBackup(key)
      const err = validateFullBundle(bundle)
      if (err) return reply.status(400).send({ error: 'Bad Request', message: `Backup ${key} is not a valid full snapshot: ${err}` })

      const actor = { email: request.userContext?.email, ip: request.ip }
      const result = await rbacBundleService.import(bundle, actor)
      return { success: true, restoredFrom: key, imported: result }
    }
  )

  // ── Back up now: export current config and upload to S3 ──
  fastify.post(
    '/bundle/backups/now',
    { preHandler: requireSuperAdmin, schema: { description: 'Export current RBAC config and upload it to S3 now.', tags: ['rbac', 'backup'] } },
    async (_request, reply) => {
      if (!backupStore.enabled()) return disabled(reply)
      const bundle = await rbacBundleService.export()
      const { key } = await backupStore.putBackup(bundle)
      return { success: true, key }
    }
  )
}

/** A restore requires a FULL snapshot; a partial export must not silently wipe. */
function validateFullBundle(bundle: AuthBundle | undefined): string | null {
  if (!bundle?.version || !bundle?.rbac) return 'Invalid bundle format — missing version or rbac fields.'
  if (bundle.version !== '1') return `Unsupported bundle version: ${bundle.version}`
  const r = bundle.rbac as Record<string, unknown>
  if (!Array.isArray(r.services) || !r.groups || !r.roles || !r.routeMaps || !Array.isArray(r.oathkeeperRules)) {
    return 'Incomplete bundle — a restore requires a full snapshot (services, groups, roles, routeMaps, oathkeeperRules).'
  }
  return null
}
