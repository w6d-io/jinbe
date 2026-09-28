import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { env } from '../config/index.js'
import { verifiedActor } from '../middleware/identity-extractor.js'
import { delegatedTokenService, PERSONAL_KEY_PREFIX } from '../services/delegated-token.service.js'
import { personalKeyService, PersonalKeyRefused } from '../services/personal-key.service.js'
import { AuthzUnavailableError } from '../authz/opa.js'
import { HydraUnavailableError } from '../services/hydra.service.js'
import { denyAudit } from '../audit/deny.js'
import { mcpGate } from '../mcp/settings.js'

/**
 * What auth-mcp asks jinbe, so hydra-admin stays closed to everything but jinbe
 * (auth-mcp src/auth/verifier.ts JinbeTokenInfoVerifier, src/auth/personal-key.ts JinbeKeyExchanger).
 *
 * POST /api/mcp/token-info               Authorization: Bearer <opaque token>   X-Actor-Token: <SA token>
 *   200 → introspection claims {active, scope, client_id, sub, exp, aud, token_use, ext{org, email, kind,
 *         subject, key_id, key_expires_at}}; 401 → not active, or refused by jinbe's rules.
 * POST /api/mcp/personal-keys/exchange   Authorization: Bearer stk_mcp_<client_id>.<secret>   X-Actor-Token
 *   200 → {access_token, expires_in}; 401 → unknown, wrong secret, expired, revoked, forbidden by the org.
 *
 * The CALLER is the actor — an allowed in-cluster ServiceAccount (DELEGATED_ACTOR_SUBJECTS, verified by
 * TokenReview) — and nobody else: not a session, not a user token, not a random pod. The Authorization
 * header carries what is being asked about. 404 on every route unless DELEGATED_TOKENS_ENABLED (the
 * deployment's ceiling). With the ceiling up but MCP turned off by an administrator (mcp/settings.ts),
 * or the token's/key's org outside its scope: 403 {error: 'mcp_disabled'}, so auth-mcp can say so.
 */

const MCP_OFF_MESSAGE = 'MCP access is turned off by an administrator.'
const MCP_ORG_MESSAGE = 'MCP access is turned off for this organization by an administrator.'

async function actorOnly(request: FastifyRequest, reply: FastifyReply) {
  if (!env.DELEGATED_TOKENS_ENABLED) return reply.status(404).send({ error: 'Not Found', message: 'Route not found' })
  if (!(await verifiedActor(request))) {
    denyAudit(request, 'mcp_actor_required')
    return reply.status(403).send({ error: 'Forbidden', message: 'This route takes an allowed in-cluster ServiceAccount token in X-Actor-Token.' })
  }
  const gate = await mcpGate()
  if (gate.off === 'unavailable') return reply.status(503).send({ error: 'unavailable', message: 'Please try again later.' })
  if (!gate.on) return reply.status(403).send({ error: 'mcp_disabled', message: MCP_OFF_MESSAGE, reason: 'disabled' })
}

/** A refusal reason that means "turned off", not "bad credential": 403 mcp_disabled rather than 401. */
function mcpOff(reply: FastifyReply, reason: string): FastifyReply | null {
  if (reason === 'mcp_disabled') return reply.status(403).send({ error: 'mcp_disabled', message: MCP_OFF_MESSAGE, reason: 'disabled' })
  if (reason === 'mcp_org_not_allowed') return reply.status(403).send({ error: 'mcp_disabled', message: MCP_ORG_MESSAGE, reason: 'org_not_allowed' })
  if (reason === 'mcp_settings_unavailable') return reply.status(503).send({ error: 'unavailable', message: 'Please try again later.' })
  return null
}

function bearerOf(request: FastifyRequest): string | null {
  const m = /^Bearer\s+(\S+)\s*$/i.exec(request.headers.authorization ?? '')
  return m ? m[1] : null
}

const refused = (reply: FastifyReply, error: string, reason: string) => reply.status(401).send({ error, message: 'Refused', reason })

const claimsSchema = {
  type: 'object',
  properties: {
    active: { type: 'boolean' },
    scope: { type: 'string' },
    client_id: { type: 'string' },
    sub: { type: 'string' },
    exp: { type: 'integer' },
    aud: { type: 'array', items: { type: 'string' } },
    token_use: { type: 'string' },
    ext: {
      type: 'object',
      properties: {
        org: { type: 'string' },
        email: { type: 'string' },
        kind: { type: 'string', enum: ['oauth', 'personal'] },
        subject: { type: 'string' },
        key_id: { type: 'string' },
        key_expires_at: { type: 'integer' },
      },
    },
  },
}
const refusalSchema = { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' }, reason: { type: 'string' } } }

export async function mcpRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', actorOnly)

  fastify.post('/token-info', {
    schema: {
      description:
        "Introspect a delegated (opaque Hydra) token for auth-mcp, with jinbe's rules: active, access token, the " +
        'delegated audience, bound to one org, an active user; personal keys re-read from their client (expiry, org ' +
        'policy). Caller: an allowed ServiceAccount in X-Actor-Token. 403 mcp_disabled when an administrator turned MCP off ' +
        "or the token's org is outside its scope.",
      tags: ['mcp'],
      response: { 200: claimsSchema, 401: refusalSchema, 403: refusalSchema, 404: refusalSchema, 503: refusalSchema },
    },
  }, async (request, reply) => {
    const token = bearerOf(request)
    if (!token || !delegatedTokenService.looksOpaque(token)) return refused(reply, 'invalid_token', 'no_token')
    const result = await delegatedTokenService.resolve(token)
    if ('error' in result) return mcpOff(reply, result.error) ?? refused(reply, 'invalid_token', result.error)
    const p = result.principal
    const sec = (ms: number) => Math.floor(ms / 1000)
    return reply.send({
      active: true,
      token_use: 'access_token',
      scope: p.tokenScope,
      client_id: p.clientId,
      // A personal key's token names the client; the user is ext.subject (auth-mcp reads it there).
      sub: p.kind === 'personal' ? p.clientId : p.subject,
      exp: sec(p.expiresAt),
      aud: p.aud,
      ext: {
        org: p.org,
        email: p.email,
        kind: p.kind,
        ...(p.kind === 'personal' ? { subject: p.subject, key_id: p.clientId, key_expires_at: sec(p.keyExpiresAt ?? p.expiresAt) } : {}),
      },
    })
  })

  fastify.post('/personal-keys/exchange', {
    schema: {
      description:
        'Exchange a personal MCP key (stk_mcp_<client_id>.<secret>) for a short-lived access token carrying the ' +
        "key's stored scopes that its holder STILL holds in the key's org (plus mcp). Refused (401) when unknown, wrong " +
        'secret, expired, or the org forbids personal keys; 403 mcp_disabled when an administrator turned MCP off or the ' +
        "key's org is outside its scope. Caller: an allowed ServiceAccount in X-Actor-Token.",
      tags: ['mcp'],
      response: {
        200: { type: 'object', properties: { access_token: { type: 'string' }, expires_in: { type: 'integer' } } },
        401: refusalSchema, 403: refusalSchema, 404: refusalSchema, 503: refusalSchema,
      },
    },
  }, async (request, reply) => {
    const raw = bearerOf(request)
    const body = raw?.startsWith(PERSONAL_KEY_PREFIX) ? raw.slice(PERSONAL_KEY_PREFIX.length) : null
    const dot = body ? body.indexOf('.') : -1
    if (!body || dot <= 0 || dot === body.length - 1) return refused(reply, 'invalid_key', 'malformed_key')
    try {
      return reply.send(await personalKeyService.exchange(body.slice(0, dot), body.slice(dot + 1)))
    } catch (err) {
      if (err instanceof PersonalKeyRefused) return mcpOff(reply, err.reason) ?? refused(reply, 'invalid_key', err.reason)
      if (err instanceof AuthzUnavailableError || err instanceof HydraUnavailableError) {
        request.log.warn({ err: (err as Error).message }, '[mcp] personal-key exchange could not be decided')
        return reply.status(503).send({ error: 'unavailable', message: 'Please try again later.' })
      }
      throw err
    }
  })
}
