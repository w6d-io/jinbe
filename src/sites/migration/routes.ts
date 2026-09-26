import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requireRecentMfa, requireSitesApply, requireSuperAdmin } from '../../middleware/require-admin.js'
import { actorOf, handle, parse } from '../http.js'
import * as migration from './migration.service.js'

/**
 * /api/admin/sites/migration — the one-time move from legacy rules to Sites (S-5, site-ux §20.3).
 * Reads under the admin plugin's `admin:read`; preview, parity and the dual run need `admin:write`;
 * cut-over and rollback change what the gateway serves: `sites:apply` (super_admin) and a recent second factor.
 */

const TAGS = ['sites']
const write = { preHandler: [requireSuperAdmin] }
const gateway = { preHandler: [requireSitesApply, requireRecentMfa] }
const doc = (description: string) => ({ schema: { description, tags: TAGS } })

const ruleId = z.string().min(1).max(128)
const previewBody = z.object({
  fixes: z.record(z.string().max(40), z.array(z.literal('pin-app')).max(1)).optional(),
  decisions: z.record(ruleId, z.literal('drop')).optional(),
}).strict()
const dualrunBody = z.object({ action: z.enum(['start', 'stop']) }).strict()
const cutoverBody = z.object({ note: z.string().max(280).optional() }).strict()

export async function migrationRoutes(fastify: FastifyInstance) {
  fastify.get('', doc('Migration state: legacy rule count, proposed groups, parity, dual run, cut-over, rollback window'),
    handle(async () => migration.getMigration()))

  fastify.post('/preview', { ...write, ...doc('Convert the live legacy rules into proposed Sites / system sites (1:1); opt-in fixes and decisions per group/rule') },
    handle(async (request) => migration.preview(parse(previewBody, request.body ?? {}), actorOf(request))))

  fastify.post('/parity', { ...write, ...doc('Match every legacy probe against the legacy and the converted rule sets (gatekit): differences and regressions') },
    handle(async () => migration.parity()))

  fastify.get('/dualrun', doc('Dual-run status: compared, same, differences, regressions, eligibility'), handle(async () => migration.dualrunStatus()))

  fastify.post('/dualrun', { ...write, ...doc('Start or stop the dual run') },
    handle(async (request) => migration.dualrun(parse(dualrunBody, request.body).action, actorOf(request))))

  fastify.post('/cutover', { ...gateway, ...doc('Create the Site CRs and wait for RulesLoaded; then new sites may be applied. 202, follow GET /migration') },
    handle(async (request, reply) => reply.status(202).send(await migration.cutover(actorOf(request), parse(cutoverBody, request.body ?? {}).note))))

  fastify.post('/rollback', { ...gateway, ...doc('Within the rollback window: restore the frozen legacy rules and pause the migrated Site CRs') },
    handle(async (request) => migration.rollback(actorOf(request))))
}
