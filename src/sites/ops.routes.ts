import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { z } from 'zod'
import { requireRecentMfa, requireSitesApply, requireSuperAdmin } from '../middleware/require-admin.js'
import { actorOf, fail, handle, nameOf, parse } from './http.js'
import { requireApply, terminal, type ApplyRecord } from './applies.js'
import { acceptDrift, drift, siteStatus } from './status.js'
import { approveRequest, createRequest, listRequests, rejectRequest } from './requests.js'
import { deleteLogo, LOGO_MAX_BYTES, LOGO_TYPES, putLogo } from './login.js'

/**
 * Day-2 routes under /api/admin/sites (S-3, S-4): apply timeline (+SSE), status, drift, apply
 * requests, and the login-page logo. Registered inside sitesRoutes, so reads need `admin:read`.
 */

const TAGS = ['sites']
const write = { preHandler: [requireSuperAdmin] }
const gateway = { preHandler: [requireSitesApply, requireRecentMfa] }
const decide = { preHandler: [requireSitesApply] }
const doc = (description: string) => ({ schema: { description, tags: TAGS } })

const applyParams = z.object({ id: z.string().min(1).max(64) })
const requestBody = z.object({ version: z.number().int().min(1), note: z.string().max(280).optional() }).strict()
const rejectBody = z.object({ reason: z.string().max(280).optional() }).strict()
const requestsQuery = z.object({ state: z.enum(['pending', 'applied', 'rejected']).optional(), site: z.string().max(40).optional() })
const SSE_POLL_MS = 500

async function events(request: FastifyRequest, reply: FastifyReply) {
  let current: ApplyRecord
  const name = nameOf(request)
  const { id } = parse(applyParams, request.params)
  try {
    current = await requireApply(name, id)
  } catch (err) {
    return fail(reply, request, err)
  }
  reply.hijack()
  const raw = reply.raw
  raw.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive', 'x-accel-buffering': 'no' })
  let closed = false
  request.raw.on('close', () => { closed = true })
  const send = (event: string, data: unknown) => raw.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  let last = JSON.stringify(current)
  send('apply', current)
  while (!closed && !terminal(current)) {
    await new Promise((r) => setTimeout(r, SSE_POLL_MS))
    const next = await requireApply(name, id).catch(() => null)
    if (!next) break
    current = next
    if (JSON.stringify(current) !== last) {
      last = JSON.stringify(current)
      send('apply', current)
    }
  }
  if (!closed) {
    send('done', { state: current.state, ...(current.code ? { code: current.code } : {}) })
    raw.end()
  }
}

export async function siteOpsRoutes(fastify: FastifyInstance) {
  fastify.addContentTypeParser([...LOGO_TYPES], { parseAs: 'buffer', bodyLimit: LOGO_MAX_BYTES }, (_request, body, done) => done(null, body))

  fastify.get('/:name/applies/:id', doc('One apply: its stages (Saved → Permissions published → Site accepted → Rules synced → Rules loaded → Address/HTTPS for vanity sites → Verified) with timings'),
    handle(async (request) => requireApply(nameOf(request), parse(applyParams, request.params).id)))

  fastify.get('/:name/applies/:id/events', doc('Server-sent events: `apply` with the whole record on every change, `done` at the end'), events)

  fastify.get('/:name/status', doc('The Site CR as the operator reports it: generation, conditions, children'),
    handle(async (request) => siteStatus(nameOf(request))))

  fastify.get('/:name/drift', doc('What differs from what kuma applied: Site CR spec and conditions, route map, roles, groups, org map'),
    handle(async (request) => drift(nameOf(request))))

  fastify.post('/:name/drift/accept', { ...gateway, ...doc('Fold the live values the intent can hold into a draft for review') },
    handle(async (request) => acceptDrift(nameOf(request), actorOf(request))))

  fastify.post('/:name/requests', { ...write, ...doc('Ask for the saved version to be applied (four-eyes: approved by another super admin when required)') },
    handle(async (request, reply) => {
      const out = await createRequest(nameOf(request), parse(requestBody, request.body), actorOf(request))
      return reply.status(201).send(out)
    }))

  fastify.get('/requests', doc('Apply requests, newest first'), handle(async (request) => listRequests(parse(requestsQuery, request.query ?? {}))))

  fastify.post('/requests/:id/approve', { ...gateway, ...doc('Approve a request: applies the version, as the approver') },
    handle(async (request) => approveRequest(parse(applyParams, request.params).id, actorOf(request))))

  fastify.post('/requests/:id/reject', { ...decide, ...doc('Reject a request, with an optional reason') },
    handle(async (request) => rejectRequest(parse(applyParams, request.params).id, actorOf(request), parse(rejectBody, request.body ?? {}).reason)))

  fastify.put('/:name/logo', { ...write, ...doc('Upload the login-page logo: PNG or WebP bytes (Content-Type image/png|image/webp), at most 256 KB; SVG refused') },
    handle(async (request) => putLogo(nameOf(request), String(request.headers['content-type'] ?? '').split(';')[0].trim(), request.body as Buffer, actorOf(request))))

  fastify.delete('/:name/logo', { ...write, ...doc('Remove the login-page logo') }, handle(async (request, reply) => {
    await deleteLogo(nameOf(request))
    return reply.status(204).send()
  }))
}
