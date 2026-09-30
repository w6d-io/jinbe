import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { z } from 'zod'
import { open } from '../policy/route-access.js'
import { effectivePermissions, specOf } from '../policy/catalog.js'
import { rights } from '../authz/opa.js'
import { demandPermissions } from '../middleware/require-permission.js'
import type { UserContext } from '../middleware/identity-extractor.js'
import { kratosService } from '../services/kratos.service.js'
import { explainRoute } from '../services/explain-route/explain-route.service.js'
import { auditAccessCheck } from '../audit/record.js'
import { auditActor } from '../utils/audit-actor.js'
import { badRequestResponseSchema, forbiddenResponseSchema, notFoundResponseSchema, unauthorizedResponseSchema } from '../schemas/response-schemas.js'

/**
 * POST /api/admin/rbac/explain-route — why jinbe (not only the gateway) accepts or refuses one call,
 * for the console and auth-mcp's `explain_admin_access`.
 *
 * About the caller by default, as they are calling now (their session, or their key through a
 * client): anybody may ask that, a key included — it tells them nothing they do not hold. About
 * somebody else (`subject`: an identity id or address) it needs access:check, like access-check, and
 * is recorded (access.checked). `via`, `aal` and `scopes` pose the question for another way in (the
 * same person through a key, at aal1…); they change the question, never what anybody holds.
 */

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const

const bodySchema = z.object({
  method: z.string().transform((m) => m.toUpperCase()).pipe(z.enum(METHODS)),
  path: z.string().max(2048).regex(/^\/[^\s?#]*$/, 'must be an absolute path with no query or fragment'),
  subject: z.string().trim().min(1).max(320).optional(),
  via: z.enum(['session', 'delegated', 'machine']).optional(),
  aal: z.enum(['aal1', 'aal2']).optional(),
  scopes: z.array(z.string().max(128)).max(200).optional(),
  clientId: z.string().max(128).optional(),
  body: z.record(z.unknown()).optional(),
})

type Question = z.infer<typeof bodySchema>

const stepSchema = {
  type: 'object',
  properties: {
    step: { type: 'string', enum: ['route', 'catalogue', 'delegation', 'platform', 'opa', 'org', 'guard'] },
    verdict: { type: 'string', enum: ['pass', 'refuse', 'info', 'skipped', 'unavailable'] },
    input: { type: 'object', additionalProperties: true },
    detail: { type: 'object', additionalProperties: true },
  },
  required: ['step', 'verdict', 'detail'],
}

export const explainRouteResponseSchema = {
  type: 'object',
  properties: {
    subject: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        email: { type: 'string' },
        via: { type: 'string' },
        aal: { type: 'string' },
        client: { type: 'boolean', description: 'What the guards pass OPA as `client` (a token, not a session)' },
        scopes: { type: 'array', items: { type: 'string' } },
      },
    },
    route: {
      type: 'object',
      properties: {
        method: { type: 'string' },
        path: { type: 'string' },
        pattern: { type: ['string', 'null'] },
        params: { type: 'object', additionalProperties: { type: 'string' } },
      },
    },
    verdict: {
      type: 'object',
      description: 'What the caller gets from the guards: 200 when all pass (the handler may still refuse)',
      properties: {
        status: { type: 'integer' },
        allowed: { type: 'boolean' },
        code: { type: 'string' },
        reason: { type: 'string' },
        message: { type: 'string' },
      },
    },
    decidedBy: { type: 'string', description: 'The guard that answered, or `handler`' },
    steps: { type: 'array', items: stepSchema },
    disagreements: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          kind: { type: 'string' },
          between: { type: 'array', items: { type: 'string' } },
          detail: { type: 'string' },
        },
      },
    },
  },
  required: ['subject', 'route', 'verdict', 'decidedBy', 'steps', 'disagreements'],
}

const isSelf = (caller: UserContext, subject: string | undefined) =>
  !subject || subject === caller.id || subject.toLowerCase() === caller.email.toLowerCase()

/** The scopes a personal key of this person would carry: what they hold, less what a key never may. */
async function keyScopes(email: string): Promise<string[]> {
  return effectivePermissions((await rights(email)).permissions).filter((p) => specOf(p)?.delegable !== 'never')
}

/** The caller as asked about: their own context, re-posed for `via` / `aal` / `scopes` when given. */
async function poseAs(base: UserContext, q: Question): Promise<UserContext> {
  const via = q.via ?? (base.authVia === 'delegated' || base.authVia === 'machine' ? base.authVia : 'session')
  const out: UserContext = { ...base, authVia: via }
  if (q.aal) out.aal = q.aal
  if (via === 'delegated') {
    const current = base.authVia === 'delegated' ? base.delegation : undefined
    out.delegation = {
      clientId: q.clientId ?? current?.clientId ?? 'explain',
      scopes: q.scopes ?? current?.scopes ?? (await keyScopes(base.email)),
      kind: current?.kind ?? 'personal',
      via: current?.via ?? 'explain',
      ...(current?.keyStepUpAt ? { keyStepUpAt: current.keyStepUpAt } : {}),
      ...(current?.keyStepUpActions !== undefined ? { keyStepUpActions: current.keyStepUpActions } : {}),
    }
    delete out.aal
  } else {
    delete out.delegation
  }
  return out
}

async function lookUp(subject: string): Promise<UserContext | null> {
  let identity
  try {
    identity = subject.includes('@') ? await kratosService.findByEmail(subject) : await kratosService.getIdentity(subject)
  } catch (err) {
    if ((err as { statusCode?: number })?.statusCode === 404) return null
    throw err
  }
  const email = identity?.traits?.email
  if (!identity || typeof email !== 'string' || email === '') return null
  const name = identity.traits?.name
  return {
    id: identity.id,
    email,
    name: typeof name === 'string' ? name : typeof name === 'object' && name ? Object.values(name).join(' ') : email,
    // Somebody else's session is not at hand: judged as a signed-in session with a second factor
    // unless `aal` says otherwise.
    authVia: 'session',
    aal: 'aal2',
  }
}

export async function explainRouteRoutes(fastify: FastifyInstance) {
  fastify.post('/explain-route', {
    ...open('self'),
    schema: {
      description:
        'Why jinbe accepts or refuses METHOD PATH for the caller (or `subject`, which needs access:check): the ' +
        'route and its guards, the catalogue permission, the delegation gate, platform holdings, OPA rbac.decision ' +
        "with the guard's exact input (and rbac.explain: which clause fired), the org trail (membership, the " +
        'roster in Redis vs OPA, manageable_orgs, org grants), and the real guards run in a dry run. ' +
        '`disagreements` lists surfaces that answer the same question differently.',
      tags: ['rbac'],
      body: {
        type: 'object',
        required: ['method', 'path'],
        properties: {
          method: { type: 'string', description: 'GET, POST, PUT, PATCH, DELETE, HEAD or OPTIONS (any case)' },
          path: { type: 'string', description: 'Absolute jinbe path, no query string, e.g. /api/organizations/3cb9…/users' },
          subject: { type: 'string', description: 'Identity id or address; default the caller. Anybody else needs access:check' },
          via: { type: 'string', enum: ['session', 'delegated', 'machine'], description: 'Pose the question for this way in; default as the caller is calling' },
          aal: { type: 'string', enum: ['aal1', 'aal2'], description: 'Sign-in level for a session' },
          scopes: { type: 'array', items: { type: 'string' }, description: "A delegated caller's token scopes; default the caller's own, or what a personal key of the subject would carry" },
          clientId: { type: 'string' },
          body: { type: 'object', additionalProperties: true, description: 'The request body, for guards that read it (a create, an edit)' },
        },
      },
      response: {
        200: explainRouteResponseSchema,
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const parsed = bodySchema.safeParse(request.body)
    if (!parsed.success) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: parsed.error.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`).join('; '),
      })
    }
    const q = parsed.data
    const caller = request.userContext
    if (!caller || !caller.id || caller.id === 'unknown' || !caller.email || caller.email === 'unknown') {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    }

    let subject: UserContext
    const self = isSelf(caller, q.subject)
    if (self) {
      subject = await poseAs(caller, q)
    } else {
      if (!(await demandPermissions(request, reply, ['access:check']))) return reply
      const found = await lookUp(q.subject!)
      if (!found) return reply.status(404).send({ error: 'Not Found', message: 'User not found' })
      subject = await poseAs(found, { ...q, via: q.via ?? 'session' })
    }

    const answer = await explainRoute(fastify, subject, { method: q.method, path: q.path, body: q.body }, { id: request.id, ip: request.ip })
    // About somebody else it discloses what they hold: who asked, about whom, is recorded.
    if (!self) {
      auditAccessCheck(auditActor(request), { email: subject.email, method: q.method, path: q.path, app: 'jinbe' }, {
        allow: answer.verdict.allowed,
        reason: answer.verdict.reason ?? (answer.verdict.allowed ? 'ok' : 'forbidden'),
      })
    }
    return reply.send(answer)
  })
}
