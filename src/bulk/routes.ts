import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { ZodError } from 'zod'
import { needs, open } from '../policy/route-access.js'
import { BulkError, executeBulk, jobFor, jobView, OP_NAMES, OPS, planBulk, planView, type OpName } from './engine.js'
import { BULK_MAX_ITEMS, callerOf } from './types.js'

/**
 * /api/admin/bulk — many changes of one kind, planned then executed (mcp-write-wave.md §3).
 *
 * One pair of routes PER OPERATION, each declaring that operation's catalogue permission: the
 * delegation gate decides a key's scope from the route's declared permission, and one route cannot
 * declare four. The catalogue attaches the step-up where it says so (groups.members:write).
 *
 *   POST /bulk/<op>/plan     {items[], params?}    → 200 plan: per-item outcome, planHash (kept 1 h)
 *   POST /bulk/<op>/execute  {planId, planHash}    → 202 job (200 when it had already finished)
 *   GET  /bulk/jobs/:id                            → the job, for the caller who started it
 *
 * For a key, a bulk call is ONE write of its write budget: map 200 routes in one call, not 200.
 */

const TAGS = ['bulk']
const DESCRIPTIONS: Record<OpName, string> = {
  'sites.routes.upsert': 'Map routes on a site DRAFT (create or replace by route id; access and gate per route). params {site}. Never saves a version, never applies',
  'users.invite': 'Create users (no groups: use groups.members.add). Items {email, name?}; params {sendInvite?} (needs users:recovery too)',
  'users.verification': 'Resend the verification link for each user\'s unverified address. Items {user: id or email}. 3 per user per 15 min, 30 per caller per hour',
  'groups.members.add': 'Add users to platform groups; never removes anything, never the caller. Items {user: id or email, groups[]}. A key cannot hand out a platform-wide group',
}

function fail(reply: FastifyReply, err: unknown) {
  if (err instanceof BulkError) return reply.status(err.statusCode).send({ error: err.code, message: err.message, ...err.extra })
  if (err instanceof ZodError) return reply.status(400).send({ error: 'invalid_request', message: 'params are not valid', issues: err.issues })
  const e = err as { statusCode?: number; code?: string; message?: string }
  if (typeof e.statusCode === 'number' && e.statusCode >= 400 && e.statusCode < 500) {
    return reply.status(e.statusCode).send({ error: e.code ?? 'error', message: e.message })
  }
  throw err
}

export async function bulkRoutes(fastify: FastifyInstance) {
  for (const name of OP_NAMES) {
    const permission = OPS[name].permission

    fastify.post(`/${name}/plan`, {
      ...needs(permission),
      schema: {
        description: `${DESCRIPTIONS[name]}. Dry run: each item judged against your rights now (ok | skip | refused | not_found — not_found only with users:read). At most ${BULK_MAX_ITEMS} items. Needs ${permission}.`,
        tags: TAGS,
        body: {
          type: 'object',
          required: ['items'],
          properties: { items: { type: 'array', minItems: 1, maxItems: BULK_MAX_ITEMS }, params: { type: 'object' } },
          additionalProperties: false,
        },
      },
    }, async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        return reply.send(planView(await planBulk(callerOf(request), name, request.body as { items?: unknown; params?: unknown })))
      } catch (err) {
        return fail(reply, err)
      }
    })

    fastify.post(`/${name}/execute`, {
      ...needs(permission),
      schema: {
        description: `Execute a plan of ${name}: planHash must be the plan's, and planning again must give the same hash (409 plan_changed, with the new plan). Each item is checked again by its own guards right before it runs; per-item results in the job. Executing a plan again answers its job (resumed if its runner stopped). Needs ${permission}.`,
        tags: TAGS,
        body: {
          type: 'object',
          required: ['planId', 'planHash'],
          properties: { planId: { type: 'string', maxLength: 64 }, planHash: { type: 'string', maxLength: 64 } },
          additionalProperties: false,
        },
      },
    }, async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const { job, started } = await executeBulk(callerOf(request), name, request.body as { planId?: unknown; planHash?: unknown })
        return reply.status(job.state === 'running' || started ? 202 : 200).send(jobView(job))
      } catch (err) {
        return fail(reply, err)
      }
    })
  }

  fastify.get('/jobs/:id', {
    ...open('self'),
    schema: {
      description: 'A bulk job you started: state, counts and each item\'s result. Anybody else\'s job answers 404.',
      tags: TAGS,
      params: { type: 'object', required: ['id'], properties: { id: { type: 'string', maxLength: 64 } } },
    },
  }, async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    try {
      return reply.send(jobView(await jobFor(callerOf(request), request.params.id)))
    } catch (err) {
      return fail(reply, err)
    }
  })
}
