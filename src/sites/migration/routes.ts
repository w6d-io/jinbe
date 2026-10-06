import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import type { Permission } from '../../policy/catalog.js'
import { actorOf, handle, parse } from '../http.js'
import * as migration from './migration.service.js'

/**
 * /api/admin/sites/migration — the one-time move from legacy rules to Sites (S-5, site-ux §20.3).
 * Reads need `sites:read`; preview, parity and the dual run `sites:write`; cut-over and rollback change
 * what the gateway serves: `sites:apply` and a recent second factor (catalogue).
 */

const TAGS = ['sites']
const doc = (permission: Permission, description: string) => ({ config: { permission }, schema: { description, tags: TAGS } })

const ruleId = z.string().min(1).max(128)
const previewBody = z.object({
  fixes: z.record(z.string().max(40), z.array(z.literal('pin-app')).max(1)).optional(),
  decisions: z.record(ruleId, z.literal('drop')).optional(),
}).strict()
const dualrunBody = z.object({ action: z.enum(['start', 'stop']) }).strict()
const cutoverBody = z.object({ note: z.string().max(280).optional() }).strict()

export async function migrationRoutes(fastify: FastifyInstance) {
  fastify.get('', doc('sites:read', 'Migration state: legacy rules to migrate (built-ins counted apart), whether sites can be applied now, proposed groups, parity, dual run, cut-over, rollback window'),
    handle(async () => migration.getMigration()))

  fastify.post('/preview', { ...doc('sites:write', 'Convert the live legacy rules into proposed Sites / system sites (1:1); opt-in fixes and decisions per group/rule') },
    handle(async (request) => migration.preview(parse(previewBody, request.body ?? {}), actorOf(request))))

  fastify.post('/parity', { ...doc('sites:write', 'Match every legacy probe against the legacy and the converted rule sets (gatekit): differences and regressions') },
    handle(async () => migration.parity()))

  fastify.get('/dualrun', doc('sites:read', 'Dual-run status: compared, same, differences, regressions, eligibility'), handle(async () => migration.dualrunStatus()))

  fastify.post('/dualrun', { ...doc('sites:write', 'Start or stop the dual run') },
    handle(async (request) => migration.dualrun(parse(dualrunBody, request.body).action, actorOf(request))))

  fastify.post('/cutover', { ...doc('sites:apply', 'Create the Site CRs and wait for RulesLoaded; then new sites may be applied. 202, follow GET /migration. 409 on a mixed gateway or when a converted rule would share a URL with a rule that stays served') },
    handle(async (request, reply) => reply.status(202).send(await migration.cutover(actorOf(request), parse(cutoverBody, request.body ?? {}).note))))

  fastify.post('/rollback', { ...doc('sites:apply', 'Within the rollback window: restore the frozen legacy rules and pause the migrated Site CRs') },
    handle(async (request) => migration.rollback(actorOf(request))))
}
