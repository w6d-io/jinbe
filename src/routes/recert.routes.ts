import { FastifyInstance, FastifyReply } from 'fastify'
import { requireAdmin } from '../middleware/require-admin.js'
import { recertService, RecertError } from '../services/recert.service.js'
import { startRecertScheduler } from '../services/recert-scheduler.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { env } from '../config/env.js'

/**
 * Access recertification campaigns (docs/specs/access-recertification.md, phase 1).
 *
 * POST   /campaigns                          create (draft)               [admin]
 * GET    /campaigns                          list with progress           [admin]
 * GET    /campaigns/:id                      campaign + items             [admin]
 * POST   /campaigns/:id/activate             generate items → active      [admin]
 * POST   /campaigns/:id/close                manual close (apply onExpiry)[admin]
 * DELETE /campaigns/:id                      draft/archived only          [admin]
 * GET    /campaigns/:id/items                items (decision/reviewer filters, pagination) [admin]
 * GET    /campaigns/:id/report               frozen completion report     [admin]
 * GET    /inbox                              caller's pending items       [any authenticated identity]
 * POST   /items/:campaignId/:itemId/decision { decision, comment? }       [assigned reviewer or admin]
 *
 * Every decision / auto-revoke is audited via auditEventService (category
 * 'access', target recert:{campaignId}[:{itemId}], severity warn on revoke).
 */
export async function recertRoutes(fastify: FastifyInstance) {
  // Deadline job — registered with the feature's routes so server.ts only
  // carries the registration line. Not started under test.
  if (env.NODE_ENV !== 'test') startRecertScheduler(fastify.log)

  const sendRecertError = (reply: FastifyReply, e: unknown) => {
    if (e instanceof RecertError) return reply.status(e.statusCode).send({ error: 'Recert Error', message: e.message })
    throw e
  }

  const campaignSchema = { type: 'object', additionalProperties: true } as const
  const itemSchema = { type: 'object', additionalProperties: true } as const

  // ── Create (draft) ──
  fastify.post(
    '/campaigns',
    {
      preHandler: requireAdmin,
      schema: {
        description: 'Create a recertification campaign (draft). Phase 1: explicit reviewer emails, one-shot schedule.',
        tags: ['recert'],
        body: {
          type: 'object',
          required: ['name', 'reviewers', 'deadline', 'onExpiry'],
          properties: {
            name: { type: 'string', minLength: 1 },
            scope: {
              type: 'object',
              properties: { groups: { type: 'array', items: { type: 'string' } } },
              additionalProperties: false,
            },
            reviewers: { type: 'array', items: { type: 'string', format: 'email' }, minItems: 1 },
            deadline: { type: 'string' },
            onExpiry: { type: 'string', enum: ['revoke', 'flag'] },
          },
        },
        response: { 201: campaignSchema },
      },
    },
    async (request, reply) => {
      const body = request.body as { name: string; scope?: { groups?: string[] }; reviewers: string[]; deadline: string; onExpiry: 'revoke' | 'flag' }
      try {
        const campaign = await recertService.createCampaign(body, auditActor(request).email)
        return reply.status(201).send(campaign)
      } catch (e) {
        return sendRecertError(reply, e)
      }
    }
  )

  // ── List ──
  fastify.get(
    '/campaigns',
    {
      preHandler: requireAdmin,
      schema: {
        description: 'List recertification campaigns with item progress (newest first).',
        tags: ['recert'],
        response: { 200: { type: 'object', properties: { campaigns: { type: 'array', items: campaignSchema } } } },
      },
    },
    async () => ({ campaigns: await recertService.listCampaigns() })
  )

  // ── Get one (campaign + items) ──
  fastify.get(
    '/campaigns/:id',
    {
      preHandler: requireAdmin,
      schema: {
        description: 'Get a campaign with its review items.',
        tags: ['recert'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
        response: { 200: { type: 'object', properties: { campaign: campaignSchema, items: { type: 'array', items: itemSchema } } } },
      },
    },
    async (request, reply) => {
      try {
        return await recertService.getCampaign((request.params as { id: string }).id)
      } catch (e) {
        return sendRecertError(reply, e)
      }
    }
  )

  // ── Activate: generate items ──
  fastify.post(
    '/campaigns/:id/activate',
    {
      preHandler: requireAdmin,
      schema: {
        description: 'Activate a draft campaign: walk groups→members via Kratos and generate one review item per (user, group) in scope.',
        tags: ['recert'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
        response: { 200: { type: 'object', properties: { campaign: campaignSchema, itemCount: { type: 'number' } } } },
      },
    },
    async (request, reply) => {
      try {
        return await recertService.activateCampaign((request.params as { id: string }).id, auditActor(request))
      } catch (e) {
        return sendRecertError(reply, e)
      }
    }
  )

  // ── Manual close ──
  fastify.post(
    '/campaigns/:id/close',
    {
      preHandler: requireAdmin,
      schema: {
        description: "Close an active campaign now: pending items get the onExpiry consequence (revoke → membership removed in Kratos, flag → marked) and the completion report is frozen.",
        tags: ['recert'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
        response: { 200: { type: 'object', properties: { campaign: campaignSchema } } },
      },
    },
    async (request, reply) => {
      try {
        const campaign = await recertService.closeCampaign((request.params as { id: string }).id, auditActor(request), 'manual')
        return { campaign }
      } catch (e) {
        return sendRecertError(reply, e)
      }
    }
  )

  // ── Delete (draft/archived only) ──
  fastify.delete(
    '/campaigns/:id',
    {
      preHandler: requireAdmin,
      schema: {
        description: 'Delete a campaign. Draft/archived only — completed campaigns and their frozen reports are audit evidence.',
        tags: ['recert'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
      },
    },
    async (request, reply) => {
      try {
        await recertService.deleteCampaign((request.params as { id: string }).id)
        return reply.status(204).send()
      } catch (e) {
        return sendRecertError(reply, e)
      }
    }
  )

  // ── Items (filters + pagination) ──
  fastify.get(
    '/campaigns/:id/items',
    {
      preHandler: requireAdmin,
      schema: {
        description: 'List a campaign\'s review items. Optional ?decision= and ?reviewer= filters; offset/limit pagination.',
        tags: ['recert'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
        querystring: {
          type: 'object',
          properties: {
            decision: { type: 'string', enum: ['pending', 'approved', 'revoked'] },
            reviewer: { type: 'string' },
            offset: { type: 'number', minimum: 0, default: 0 },
            limit: { type: 'number', minimum: 1, maximum: 500, default: 100 },
          },
        },
        response: { 200: { type: 'object', properties: { items: { type: 'array', items: itemSchema }, total: { type: 'number' } } } },
      },
    },
    async (request, reply) => {
      const { decision, reviewer, offset = 0, limit = 100 } = request.query as { decision?: string; reviewer?: string; offset?: number; limit?: number }
      try {
        const { items } = await recertService.getCampaign((request.params as { id: string }).id)
        const filtered = items.filter(
          (i) => (!decision || i.decision === decision) && (!reviewer || i.reviewer === reviewer.toLowerCase())
        )
        return { items: filtered.slice(offset, offset + limit), total: filtered.length }
      } catch (e) {
        return sendRecertError(reply, e)
      }
    }
  )

  // ── Completion report (frozen JSON) ──
  fastify.get(
    '/campaigns/:id/report',
    {
      preHandler: requireAdmin,
      schema: {
        description: 'Frozen completion report (written once at close) — counters, per-reviewer completion, full item list, compliance header (ISO 27001 A.9.2.5 / SOC 2 CC6.2–CC6.3).',
        tags: ['recert'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
        querystring: { type: 'object', properties: { format: { type: 'string', enum: ['json'] } } },
        response: { 200: { type: 'object', additionalProperties: true } },
      },
    },
    async (request, reply) => {
      try {
        const report = await recertService.getReport((request.params as { id: string }).id)
        reply.header('Content-Disposition', `attachment; filename="recert-report-${report.campaignId}.json"`)
        return report
      } catch (e) {
        return sendRecertError(reply, e)
      }
    }
  )

  // ── Reviewer inbox — any authenticated identity (email from the session context) ──
  fastify.get(
    '/inbox',
    {
      schema: {
        description: "The caller's pending review items across active campaigns. No admin gate: reviewers are arbitrary identities.",
        tags: ['recert'],
        response: { 200: { type: 'object', properties: { items: { type: 'array', items: itemSchema } } } },
      },
    },
    async (request, reply) => {
      const email = request.userContext?.email
      if (!email || email === 'unknown') {
        return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
      }
      return { items: await recertService.getInbox(email) }
    }
  )

  // ── Decision — assigned reviewer or admin ──
  fastify.post(
    '/items/:campaignId/:itemId/decision',
    {
      schema: {
        description: 'Record a decision on a review item (assigned reviewer or admin). revoke requires a comment and is applied immediately (membership removed in Kratos). Self-review is blocked.',
        tags: ['recert'],
        params: {
          type: 'object',
          required: ['campaignId', 'itemId'],
          properties: { campaignId: { type: 'string' }, itemId: { type: 'string' } },
        },
        body: {
          type: 'object',
          required: ['decision'],
          properties: {
            decision: { type: 'string', enum: ['approved', 'revoked'] },
            comment: { type: 'string', maxLength: 2000 },
          },
        },
        response: { 200: { type: 'object', properties: { item: itemSchema } } },
      },
    },
    async (request, reply) => {
      const email = request.userContext?.email
      if (!email || email === 'unknown') {
        return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
      }
      const { campaignId, itemId } = request.params as { campaignId: string; itemId: string }
      const { decision, comment } = request.body as { decision: 'approved' | 'revoked'; comment?: string }

      try {
        // Authorization: the assigned reviewer may always decide their items;
        // anyone else must pass the admin gate (requireAdmin sends its own 403).
        const item = await recertService.getCampaign(campaignId).then(({ items }) => items.find((i) => i.id === itemId))
        if (!item) return reply.status(404).send({ error: 'Not Found', message: `Item not found: ${itemId}` })
        if (item.reviewer !== email.toLowerCase()) {
          await requireAdmin(request, reply)
          if (reply.sent) return
        }
        const decided = await recertService.decide(campaignId, itemId, decision, comment, auditActor(request))
        return { item: decided }
      } catch (e) {
        return sendRecertError(reply, e)
      }
    }
  )
}
