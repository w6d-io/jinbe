import { FastifyInstance } from 'fastify'
import { requireSuperAdmin } from '../middleware/require-admin.js'
import { rbacBundleService, type AuthBundle, ALL_BUNDLE_SECTIONS, type BundleSection, BundleValidationError } from '../services/rbac-bundle.service.js'
import { backupStore } from '../services/backup-store.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'

/**
 * Auth config bundle export / import + S3 backup routes.
 *
 * GET  /api/admin/rbac/bundle/export           — download bundle (optionally ?sections=)
 * POST /api/admin/rbac/bundle/import           — restore from an uploaded bundle (full replace)
 * GET  /api/admin/rbac/bundle/backups          — list S3 backup snapshots
 * POST /api/admin/rbac/bundle/backups/restore  — restore from an S3 snapshot key
 * POST /api/admin/rbac/bundle/backups/now      — export current config and upload to S3
 * GET  /api/admin/rbac/bundle/history          — pre-import snapshot history (no bundle payloads)
 * POST /api/admin/rbac/bundle/history/:id/rollback — restore a history entry's snapshot (full replace)
 *
 * All require super_admin. Internal cluster requests bypass the check (the
 * backup CronJob uses the internal Host header).
 */
export async function rbacBundleRoutes(fastify: FastifyInstance) {
  const disabled = (reply: import('fastify').FastifyReply) =>
    reply.status(501).send({ error: 'Not Implemented', code: 'backup_disabled', message: 'S3 backup is not enabled on this deployment.' })

  // Fail-closed rule validation → 400 listing WHICH rules failed and why. The
  // global error handler only forwards `message`, so the failures array is
  // attached here on every path that funnels into rbacBundleService.import().
  const badBundle = (reply: import('fastify').FastifyReply, err: BundleValidationError) =>
    reply.status(400).send({ error: 'Bad Request', message: err.message, failures: err.failures })

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
      // Audit the export — this is an exfil path (the whole RBAC config leaves
      // the cluster). Actor is always a resolvable super_admin here.
      const a = auditActor(request)
      auditEventService.emit({
        category: 'rbac', kind: 'change', verb: 'export', target: 'bundle',
        result: 'applied', severity: 'warn',
        actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
        requestId: a.requestId,
        details: { sections: sections ?? 'full' },
      }).catch(() => {})
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
        description: 'Import an auth bundle — restores RBAC config. Body must be a full snapshot; ?sections=services,groups,… applies only those parts (override/add, no prune), omitted = full 1:1 restore.',
        tags: ['rbac', 'backup'],
        querystring: { type: 'object', properties: { sections: { type: 'string' } } },
        body: { type: 'object', additionalProperties: true },
        response: {
          200: { type: 'object', properties: { success: { type: 'boolean' }, imported: { type: 'object', additionalProperties: true } } },
        },
      },
    },
    async (request, reply) => {
      const bundle = request.body as AuthBundle
      // Uploaded file must still be a FULL snapshot — a selective import picks
      // which parts of that snapshot to apply, it does not accept a partial file.
      const err = validateFullBundle(bundle)
      if (err) return reply.status(400).send({ error: 'Bad Request', message: err })

      const raw = (request.query as { sections?: string })?.sections
      const sections = raw
        ? raw.split(',').map((s) => s.trim()).filter((s): s is BundleSection => (ALL_BUNDLE_SECTIONS as string[]).includes(s))
        : undefined

      try {
        const result = await rbacBundleService.import(bundle, auditActor(request), sections)
        return { success: true, imported: result }
      } catch (e) {
        if (e instanceof BundleValidationError) return badBundle(reply, e)
        throw e
      }
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

      const a = auditActor(request)
      // Record the S3 snapshot key this restore came from (import() emits the
      // config-diff event; this records the provenance of the restore).
      auditEventService.emit({
        category: 'rbac', kind: 'change', verb: 'restore', target: `backup:${key}`,
        result: 'applied', severity: 'high',
        actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
        requestId: a.requestId, details: { snapshotKey: key },
      }).catch(() => {})
      try {
        const result = await rbacBundleService.import(bundle, a, undefined, 'pre-restore')
        return { success: true, restoredFrom: key, imported: result }
      } catch (e) {
        if (e instanceof BundleValidationError) return badBundle(reply, e)
        throw e
      }
    }
  )

  // ── Back up now: export current config and upload to S3 ──
  fastify.post(
    '/bundle/backups/now',
    { preHandler: requireSuperAdmin, schema: { description: 'Export current RBAC config and upload it to S3 now.', tags: ['rbac', 'backup'] } },
    async (request, reply) => {
      if (!backupStore.enabled()) return disabled(reply)
      const bundle = await rbacBundleService.export()
      const { key } = await backupStore.putBackup(bundle)
      const a = auditActor(request)
      auditEventService.emit({
        category: 'rbac', kind: 'change', verb: 'backup', target: `backup:${key}`,
        result: 'applied',
        actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
        requestId: a.requestId, details: { snapshotKey: key },
      }).catch(() => {})
      return { success: true, key }
    }
  )

  // ── Pre-import snapshot history (bundle payloads omitted — counts only) ──
  fastify.get(
    '/bundle/history',
    {
      preHandler: requireSuperAdmin,
      schema: {
        description: 'List pre-import/restore/rollback snapshots (newest first, cap 10). Entries carry per-section counts, not the bundle payload.',
        tags: ['rbac', 'backup'],
        response: {
          200: {
            type: 'object',
            properties: {
              history: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    takenAt: { type: 'string' },
                    actor: { type: ['string', 'null'] },
                    reason: { type: 'string', enum: ['pre-import', 'pre-restore', 'pre-rollback'] },
                    counts: { type: 'object', additionalProperties: { type: 'number' } },
                  },
                },
              },
            },
          },
        },
      },
    },
    async () => {
      const history = await rbacBundleService.listImportHistory()
      return { history }
    }
  )

  // ── Roll back to a history entry's snapshot (full replace) ──
  fastify.post(
    '/bundle/history/:id/rollback',
    {
      preHandler: requireSuperAdmin,
      schema: {
        description: "Restore the RBAC config snapshot of a history entry (full replace). The current state is snapshotted first (reason 'pre-rollback'), so a rollback is itself reversible.",
        tags: ['rbac', 'backup'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
        response: {
          200: { type: 'object', properties: { success: { type: 'boolean' }, rolledBackTo: { type: 'object', additionalProperties: true }, imported: { type: 'object', additionalProperties: true } } },
        },
      },
    },
    async (request, reply) => {
      const { id } = request.params as { id: string }
      const a = auditActor(request)
      try {
        const { entry, result } = await rbacBundleService.rollback(id, a)
        // Record the provenance of the rollback (import() emits the config-diff
        // event; this records WHICH snapshot the state was rolled back to).
        auditEventService.emit({
          category: 'rbac', kind: 'change', verb: 'rollback', target: `history:${id}`,
          result: 'applied', severity: 'high',
          actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
          requestId: a.requestId, details: { historyId: id, takenAt: entry.takenAt, reason: entry.reason },
        }).catch(() => {})
        return { success: true, rolledBackTo: entry, imported: result }
      } catch (e) {
        if (e instanceof BundleValidationError) return badBundle(reply, e)
        throw e
      }
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
