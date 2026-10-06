import { FastifyInstance } from 'fastify'
import { badRequestResponseSchema, conflictResponseSchema } from '../schemas/response-schemas.js'
import { needs } from '../policy/route-access.js'
import { rbacBundleService, type AuthBundle, ALL_BUNDLE_SECTIONS, type BundleSection, bundleProblem } from '../services/rbac-bundle.service.js'
import { backupStore } from '../services/backup-store.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'

/**
 * Backup & restore: the snapshot (rbac-bundle.service.ts) as a file, in S3, and the import history.
 *
 * GET  /api/admin/rbac/bundle/export           — download the current snapshot (optionally ?sections=)
 * POST /api/admin/rbac/bundle/import           — restore from an uploaded snapshot (full replace, or ?sections=)
 * GET  /api/admin/rbac/bundle/backups          — list S3 backup snapshots
 * GET  /api/admin/rbac/bundle/backups/download — download one S3 snapshot (?key=)
 * POST /api/admin/rbac/bundle/backups/restore  — restore from an S3 snapshot key
 * POST /api/admin/rbac/bundle/backups/now      — export current config and upload to S3
 * GET  /api/admin/rbac/bundle/history          — pre-import snapshot history (no bundle payloads)
 * POST /api/admin/rbac/bundle/history/:id/rollback — restore a history entry's snapshot (full replace)
 *
 * Reads need policy.bundle:read, writes policy.bundle:write and a recent second factor (catalogue).
 */
export async function rbacBundleRoutes(fastify: FastifyInstance) {
  const disabled = (reply: import('fastify').FastifyReply) =>
    reply.status(501).send({ error: 'Not Implemented', code: 'backup_disabled', message: 'S3 backup is not enabled on this deployment.' })

  // ── Export (optionally a subset of sections) ──
  fastify.get(
    '/bundle/export',
    {
      ...needs('policy.bundle:read'),
      schema: {
        description: 'Download the current snapshot (format 2): the RBAC model, people\'s org roles and direct grants, site intents and versions, platform settings, the organization records, sign-up stores and metadata. Not accounts or OAuth clients. ?sections=services,groups,… narrows it; omitted = full 1:1 snapshot.',
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
      // the cluster). Actor is always a resolvable policy.bundle:read holder here.
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
      ...needs('policy.bundle:write'),
      // A full replace of the access model: policy.bundle:write + a fresh second factor (catalogue).
      schema: {
        description: 'Restore from a snapshot file (format 1 or 2). Body must be a full snapshot; ?sections=services,groups,… applies only those parts (override/add, no prune), omitted = full 1:1 restore (each section the file carries replaces what is there; sites that exist are kept; organizations are never deleted, and org data is restored only for the organizations the file has). Gateway rules in a format-1 file are never restored. Every applied site is published again afterwards (`imported.sites`). 409 (nothing written) when the resulting route maps tie two services on one route at the same specificity.',
        tags: ['rbac', 'backup'],
        querystring: { type: 'object', properties: { sections: { type: 'string' } } },
        body: { type: 'object', additionalProperties: true },
        response: {
          200: { type: 'object', properties: { success: { type: 'boolean' }, imported: { type: 'object', additionalProperties: true } } },
          400: badRequestResponseSchema,
          409: conflictResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const bundle = request.body as AuthBundle
      // Uploaded file must still be a FULL snapshot — a selective import picks
      // which parts of that snapshot to apply, it does not accept a partial file.
      const err = bundleProblem(bundle)
      if (err) return reply.status(400).send({ error: 'Bad Request', message: err })

      const raw = (request.query as { sections?: string })?.sections
      const sections = raw
        ? raw.split(',').map((s) => s.trim()).filter((s): s is BundleSection => (ALL_BUNDLE_SECTIONS as string[]).includes(s))
        : undefined

      const result = await rbacBundleService.import(bundle, auditActor(request), sections)
      return { success: true, imported: result }
    }
  )

  // ── List S3 backup snapshots ──
  fastify.get(
    '/bundle/backups',
    { ...needs('policy.bundle:read'), schema: { description: 'List RBAC bundle backups in S3.', tags: ['rbac', 'backup'] } },
    async (_request, reply) => {
      if (!backupStore.enabled()) return disabled(reply)
      const backups = await backupStore.listBackups()
      return { ...backupStore.config(), backups }
    }
  )

  // ── Download one S3 snapshot: the same file a restore reads ──
  fastify.get(
    '/bundle/backups/download',
    {
      ...needs('policy.bundle:read'),
      schema: {
        description: 'Download one S3 backup snapshot as a file (?key= from the list).',
        tags: ['rbac', 'backup'],
        querystring: { type: 'object', required: ['key'], properties: { key: { type: 'string' } } },
        response: { 200: { type: 'object', additionalProperties: true } },
      },
    },
    async (request, reply) => {
      if (!backupStore.enabled()) return disabled(reply)
      const { key } = request.query as { key: string }
      const bundle = await backupStore.getBackup(key)
      // An exfil path like the export: audited the same way.
      const a = auditActor(request)
      auditEventService.emit({
        category: 'rbac', kind: 'change', verb: 'export', target: `backup:${key}`,
        result: 'applied', severity: 'warn',
        actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
        requestId: a.requestId, details: { snapshotKey: key },
      }).catch(() => {})
      const filename = `auth-backup-${key.split('/').pop() ?? 'snapshot.json'}`
      reply.header('Content-Disposition', `attachment; filename="${filename.replace(/[^\w.-]/g, '_')}"`)
      reply.header('Content-Type', 'application/json')
      return bundle
    }
  )

  // ── Restore from an S3 snapshot key ──
  fastify.post(
    '/bundle/backups/restore',
    {
      ...needs('policy.bundle:write'),
      // A full replace of the access model: policy.bundle:write + a fresh second factor (catalogue).
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
      const err = bundleProblem(bundle)
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
      const result = await rbacBundleService.import(bundle, a, undefined, 'pre-restore')
      return { success: true, restoredFrom: key, imported: result }
    }
  )

  // ── Back up now: export current config and upload to S3 ──
  fastify.post(
    '/bundle/backups/now',
    { ...needs('policy.bundle:write'), schema: { description: 'Export current RBAC config and upload it to S3 now.', tags: ['rbac', 'backup'] } },
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
      ...needs('policy.bundle:read'),
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
      ...needs('policy.bundle:write'),
      // A full replace of the access model: policy.bundle:write + a fresh second factor (catalogue).
      schema: {
        description: "Restore the RBAC config snapshot of a history entry (full replace). The current state is snapshotted first (reason 'pre-rollback'), so a rollback is itself reversible.",
        tags: ['rbac', 'backup'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
        response: {
          200: { type: 'object', properties: { success: { type: 'boolean' }, rolledBackTo: { type: 'object', additionalProperties: true }, imported: { type: 'object', additionalProperties: true } } },
        },
      },
    },
    async (request) => {
      const { id } = request.params as { id: string }
      const a = auditActor(request)
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
    }
  )
}
