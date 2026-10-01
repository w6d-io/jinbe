import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { env } from '../config/index.js'
import { needs, open } from '../policy/route-access.js'
import { auditActor } from '../utils/audit-actor.js'
import { clientIp } from '../utils/client-ip.js'
import { mcpGate } from '../mcp/settings.js'
import { oauthGate, oauthIssuer, authOrigin } from './issuer.js'
import { authorizationServerMetadata } from './metadata.js'
import { createMcpClient, ipNet, MAX_UNCONSENTED, registrationBrake, unconsentedClients, validateRegistration } from './register.js'
import { loginStep } from './login.js'
import { consentScreen, decideConsent, type ConsentDecision } from './consent.js'
import { listConnections, revokeAllConnections, revokeConnection } from './connections.js'
import { FlowError } from './flow.js'
import { oauthAudit } from './audit.js'
import { StepUpRefusal, completeStepUpRequest, createStepUpRequest, describeStepUpRequest } from './step-up-refresh.js'
import { PER_CALLER_PER_MINUTE, providerCeiling, providerRateKey } from './provider-limit.js'
import { componentLogger } from '../telemetry/logger.js'
import { notFoundResponseSchema, serviceUnavailableResponseSchema, unauthorizedResponseSchema, forbiddenResponseSchema } from '../schemas/response-schemas.js'

/**
 * Browser sign-in for MCP clients (docs: research mcp-oauth design; owner decisions 2026-09-30).
 *
 *   Hydra host (rule `mcp-oauth-as`, answered only for that Host, 404 elsewhere or without MCP_OAUTH_ISSUER):
 *     GET  /.well-known/oauth-authorization-server   RFC 8414 metadata (metadata.ts)
 *     POST /oauth2/register                          locked-down client registration (register.ts)
 *   login-ui, server side, with the visitor's Kratos cookies (session only; a bearer is refused):
 *     GET  /api/public/oauth2/login                  the login provider (login.ts)
 *     GET  /api/public/oauth2/consent                the consent screen (consent.ts)
 *     POST /api/public/oauth2/consent                allow / deny (Origin must be the auth host)
 *   kuma:
 *     GET    /api/me/mcp/connections                 your signed-in apps (connections.ts)
 *     DELETE /api/me/mcp/connections/:clientId       disconnect one
 *     DELETE /api/me/mcp/connections                 disconnect all of yours
 *     DELETE /api/admin/users/:id/mcp-connections    disconnect all of a person's (sessions:revoke)
 */

const oauthError = { type: 'object', properties: { error: { type: 'string' }, error_description: { type: 'string' } } }
const flowError = { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } }
const flowAnswer = {
  type: 'object',
  properties: {
    action: { type: 'string', enum: ['redirect', 'refused'] },
    to: { type: 'string' },
    reason: { type: 'string' },
  },
}

const onIssuerHost = (request: FastifyRequest): boolean => {
  const iss = oauthIssuer()
  return !!iss && String(request.headers.host ?? '').toLowerCase() === iss.host.toLowerCase()
}

const notFound = (reply: FastifyReply) => reply.status(404).send({ error: 'Not Found', message: 'Route not found' })

export async function oauthAuthorizationServerRoutes(fastify: FastifyInstance) {
  fastify.get('/.well-known/oauth-authorization-server', {
    config: { access: 'public', rateLimit: { max: 300, timeWindow: '1 minute' } },
    schema: {
      description:
        'RFC 8414 authorization-server metadata for MCP clients, on the Hydra host only (MCP_OAUTH_ISSUER). The issuer ' +
        'is Hydra\'s verbatim; PKCE S256 only, public clients, registration at <issuer>/oauth2/register.',
      tags: ['oauth'],
    },
  }, async (request, reply) => {
    const iss = oauthIssuer()
    if (!iss || !onIssuerHost(request)) return notFound(reply)
    reply.header('cache-control', 'public, max-age=300')
    return authorizationServerMetadata(iss)
  })

  fastify.post('/oauth2/register', {
    config: { access: 'public', rateLimit: { max: 30, timeWindow: '1 minute' } },
    bodyLimit: 16 * 1024,
    schema: {
      description:
        'Register an MCP client (RFC 7591 subset), on the Hydra host only. Loopback http redirect URIs with an explicit port ' +
        '(localhost, 127.0.0.1, [::1]), a public client (none), authorization_code + refresh_token. The audience, lifetimes and ' +
        'metadata are forced; no secret and no registration access token are issued. 403 access_denied when MCP or browser ' +
        'sign-in is off; 429 over the per-network or daily limit; 503 when too many registrations await consent.',
      tags: ['oauth'],
      response: {
        201: {
          type: 'object',
          properties: {
            client_id: { type: 'string' },
            client_id_issued_at: { type: 'integer' },
            client_name: { type: 'string' },
            redirect_uris: { type: 'array', items: { type: 'string' } },
            grant_types: { type: 'array', items: { type: 'string' } },
            response_types: { type: 'array', items: { type: 'string' } },
            token_endpoint_auth_method: { type: 'string' },
            scope: { type: 'string' },
          },
        },
        400: oauthError, 403: oauthError, 404: flowError, 429: oauthError, 503: oauthError,
      },
    },
  }, async (request, reply) => {
    if (!oauthIssuer() || !onIssuerHost(request)) return notFound(reply)
    reply.header('cache-control', 'no-store')
    const gate = await oauthGate()
    if (!gate.on || !env.DELEGATED_TOKEN_AUDIENCE) {
      if (gate.on === false && gate.reason === 'unavailable') return reply.status(503).send({ error: 'temporarily_unavailable', error_description: 'Try again later.' })
      return reply.status(403).send({ error: 'access_denied', error_description: 'Signing in to AI assistants is not available on this server.' })
    }
    const valid = validateRegistration(request.body)
    if ('error' in valid) return reply.status(valid.status).send({ error: valid.error, error_description: valid.error_description })

    const net = ipNet(clientIp(request))
    const brake = await registrationBrake(net)
    if (brake) {
      if (brake.retryAfter) reply.header('Retry-After', String(brake.retryAfter))
      return reply.status(brake.status).send({ error: brake.error, error_description: brake.error_description })
    }
    const ua = (request.headers['user-agent'] as string | undefined) ?? null
    try {
      if ((await unconsentedClients()) >= MAX_UNCONSENTED) {
        componentLogger('oauth').error({ cap: MAX_UNCONSENTED }, 'too many unconsented MCP client registrations: refusing new ones (abuse?)')
        return reply.status(503).send({ error: 'temporarily_unavailable', error_description: 'Registration is paused. Try again later.' })
      }
      const client = await createMcpClient(valid, { net, ua, audience: env.DELEGATED_TOKEN_AUDIENCE })
      oauthAudit('mcp.oauth.client_registered', {
        actor: { id: null, email: null, ip: net, ua, type: 'anonymous', requestId: auditActor(request).requestId },
        targetId: client.client_id,
        details: { client_name: client.client_name, redirect_hosts: client.redirect_uris.map((u) => new URL(u).host), scopes: client.scope.split(' ').length, ip_net: net },
      })
      return reply.status(201).send(client)
    } catch (err) {
      componentLogger('oauth').warn({ reason: (err as Error).message }, 'MCP client registration failed')
      return reply.status(503).send({ error: 'temporarily_unavailable', error_description: 'Registration is unavailable right now. Try again later.' })
    }
  })
}

/** login-ui's calls carry the visitor's Kratos cookies and nothing else: a bearer is not the visitor. */
async function sessionOnly(request: FastifyRequest, reply: FastifyReply) {
  reply.header('cache-control', 'private, no-store')
  if (request.headers.authorization) {
    return reply.status(403).send({ error: 'session_only', message: 'This route takes the visitor\'s own session, not a token.' })
  }
}

function flowFailed(err: unknown, reply: FastifyReply) {
  if (err instanceof FlowError) return reply.status(err.status).send({ error: err.code, message: err.message })
  if (err instanceof StepUpRefusal) {
    if (err.retryAfter) reply.header('Retry-After', String(err.retryAfter))
    return reply.status(err.status).send({ error: err.code, message: err.message })
  }
  throw err
}

const ctxOf = (request: FastifyRequest) => ({
  cookie: request.headers.cookie,
  ip: clientIp(request) ?? null,
  ua: (request.headers['user-agent'] as string | undefined) ?? null,
  requestId: (request.headers['x-request-id'] as string | undefined) ?? null,
})

const CHALLENGE = { type: 'string', minLength: 1, maxLength: 4096 }

export async function oauthProviderRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', providerCeiling)
  fastify.addHook('preHandler', sessionOnly)
  // login-ui asks from its own pods: keyed on the visitor, never on the pod (provider-limit.ts).
  const limit = { max: PER_CALLER_PER_MINUTE, timeWindow: '1 minute', keyGenerator: providerRateKey }

  fastify.get('/login', {
    config: { access: 'public', rateLimit: limit },
    schema: {
      description:
        "Hydra login provider for MCP clients, for login-ui (the visitor's Kratos cookies). {action:'redirect', to}: Kratos " +
        "login, aal2, aal2 refresh, 2FA enrolment, or Hydra after accepting; {action:'refused', reason, to}: show why, then " +
        'follow `to` (Hydra reject). 404 challenge_unknown when expired or used.',
      tags: ['oauth'],
      querystring: { type: 'object', required: ['login_challenge'], properties: { login_challenge: CHALLENGE } },
      response: { 200: flowAnswer, 400: flowError, 403: flowError, 404: flowError, 503: flowError },
    },
  }, async (request, reply) => {
    try {
      return await loginStep((request.query as { login_challenge: string }).login_challenge, ctxOf(request))
    } catch (err) {
      return flowFailed(err, reply)
    }
  })

  fastify.get('/consent', {
    config: { access: 'public', rateLimit: limit },
    schema: {
      description:
        "The consent screen for an MCP client, for login-ui (the visitor's Kratos cookies): the unverified client, the account, " +
        'the permissions asked that you hold (labels, sensitivity), whether protected actions are offered and until when, and ' +
        "the sign-in's absolute end. Or {action:'refused', reason, to}. 401 without a session, 403 wrong_account.",
      tags: ['oauth'],
      querystring: { type: 'object', required: ['consent_challenge'], properties: { consent_challenge: CHALLENGE } },
      response: {
        200: {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['show', 'refused'] },
            to: { type: 'string' },
            reason: { type: 'string' },
            client: {
              type: 'object',
              properties: {
                client_id: { type: 'string' }, name: { type: 'string' }, name_verified: { type: 'boolean' },
                redirect_host: { type: ['string', 'null'] }, registered_at: { type: ['string', 'null'] },
              },
            },
            account: { type: 'object', properties: { email: { type: 'string' }, subject: { type: 'string' } } },
            requested: { type: 'array', items: { type: 'string' } },
            offline_access: { type: 'boolean' },
            catalog: {
              type: 'array',
              items: {
                type: 'object',
                properties: { scope: { type: 'string' }, group: { type: 'string' }, label: { type: 'string' }, sensitivity: { type: 'string' }, protected: { type: 'boolean' } },
              },
            },
            protectedActions: {
              type: 'object',
              properties: { offered: { type: 'boolean' }, until: { type: ['string', 'null'] }, hours: { type: 'integer' }, permissions: { type: 'array', items: { type: 'string' } } },
            },
            grantExpiresAt: { type: 'string' },
          },
        },
        400: flowError, 401: flowError, 403: flowError, 404: flowError, 503: flowError,
      },
    },
  }, async (request, reply) => {
    try {
      return await consentScreen((request.query as { consent_challenge: string }).consent_challenge, ctxOf(request))
    } catch (err) {
      return flowFailed(err, reply)
    }
  })

  const REQ = { type: 'string', minLength: 16, maxLength: 64, pattern: '^[A-Za-z0-9_-]+$' }
  const stepUpAnswer = {
    type: 'object',
    properties: {
      action: { type: 'string', enum: ['show', 'redirect', 'done'] },
      to: { type: 'string' },
      kind: { type: 'string', enum: ['oauth', 'personal'] },
      client_id: { type: 'string' },
      client_name: { type: 'string' },
      expiresAt: { type: 'string' },
      step_up_at: { type: 'string' },
      step_up_until: { type: ['string', 'null'] },
    },
  }

  fastify.get('/step-up', {
    config: { access: 'public', rateLimit: limit },
    schema: {
      description:
        "What a second-factor refresh link would refresh, for login-ui (the visitor's Kratos cookies; nothing is consumed): " +
        "{action:'show', kind, client_id, client_name, expiresAt}. 401 without a session, 403 wrong_account (not the holder) | " +
        'protected_actions_off | mcp_disabled, 404 request_unknown (expired or used), 409 protected_actions_not_allowed | credential_gone.',
      tags: ['oauth'],
      querystring: { type: 'object', required: ['req'], properties: { req: REQ } },
      response: { 200: stepUpAnswer, 400: flowError, 401: flowError, 403: flowError, 404: flowError, 409: flowError, 503: flowError },
    },
  }, async (request, reply) => {
    try {
      return await describeStepUpRequest((request.query as { req: string }).req, ctxOf(request))
    } catch (err) {
      return flowFailed(err, reply)
    }
  })

  fastify.post('/step-up', {
    config: { access: 'public', rateLimit: limit },
    schema: {
      description:
        "Complete a second-factor refresh link, for login-ui's server action (the visitor's Kratos cookies, Origin = the auth " +
        "host). The visitor must be the credential's holder with a second factor proven in the last 2 minutes, else " +
        "{action:'redirect', to} (Kratos aal2 refresh, back to the link). Then the key or sign-in gets a fresh proof for " +
        "protected actions: {action:'done', kind, client_id, client_name, step_up_at, step_up_until}. Single use.",
      tags: ['oauth'],
      body: { type: 'object', required: ['req'], additionalProperties: false, properties: { req: REQ } },
      response: { 200: stepUpAnswer, 400: flowError, 401: flowError, 403: flowError, 404: flowError, 409: flowError, 503: flowError },
    },
  }, async (request, reply) => {
    const expected = authOrigin()
    if (!expected || request.headers.origin !== expected) {
      return reply.status(403).send({ error: 'bad_origin', message: 'This must come from the sign-in page.' })
    }
    try {
      return await completeStepUpRequest((request.body as { req: string }).req, ctxOf(request))
    } catch (err) {
      return flowFailed(err, reply)
    }
  })

  fastify.post('/consent', {
    config: { access: 'public', rateLimit: limit },
    schema: {
      description:
        "Allow or deny an MCP client, for login-ui's server action (the visitor's Kratos cookies, Origin = the auth host). " +
        "mode 'all' follows your permissions at each call; 'chosen' is the ticked subset of what you hold. protected_actions " +
        "only when offered. {action:'redirect', to} or {action:'refused', reason, to}.",
      tags: ['oauth'],
      body: {
        type: 'object',
        required: ['consent_challenge', 'decision'],
        additionalProperties: false,
        properties: {
          consent_challenge: CHALLENGE,
          decision: { type: 'string', enum: ['allow', 'deny'] },
          mode: { type: 'string', enum: ['all', 'chosen'] },
          scopes: { type: 'array', maxItems: 500, items: { type: 'string', maxLength: 128 } },
          protected_actions: { type: 'boolean' },
        },
      },
      response: { 200: flowAnswer, 400: flowError, 401: flowError, 403: flowError, 404: flowError, 503: flowError },
    },
  }, async (request, reply) => {
    const expected = authOrigin()
    if (!expected || request.headers.origin !== expected) {
      return reply.status(403).send({ error: 'bad_origin', message: 'This decision must come from the sign-in page.' })
    }
    try {
      return await decideConsent(request.body as ConsentDecision, ctxOf(request))
    } catch (err) {
      return flowFailed(err, reply)
    }
  })
}

/** A person, in a browser, while MCP is on — a delegated caller reaches only the revoke (delegation-gate.ts). */
async function personOnly(request: FastifyRequest, reply: FastifyReply) {
  const gate = await mcpGate()
  if (gate.off === 'unavailable') return reply.status(503).send({ error: 'settings_unavailable', message: 'The AI assistant settings cannot be read right now.' })
  if (!gate.on) return reply.status(404).send({ error: 'Not Found', message: 'AI assistants are turned off.' })
  const via = request.userContext?.authVia
  if (via === 'delegated' && request.method === 'DELETE') return
  if (via === 'machine' || via === 'delegated') {
    return reply.status(403).send({ error: 'Forbidden', message: 'Signed-in apps are managed by a person, in a browser.' })
  }
}

const connectionSchema = {
  type: 'object',
  properties: {
    client_id: { type: 'string' },
    client_name: { type: 'string' },
    redirect_host: { type: ['string', 'null'] },
    granted_at: { type: ['string', 'null'] },
    grant_expires_at: { type: ['string', 'null'] },
    scope_mode: { type: 'string', enum: ['all', 'chosen'] },
    scopes: { type: 'array', items: { type: 'string' } },
    step_up_actions: { type: 'boolean' },
    step_up_until: { type: ['string', 'null'] },
    last_used_at: { type: ['string', 'null'] },
  },
}

function hydraDown(err: unknown, reply: FastifyReply) {
  componentLogger('oauth').warn({ reason: (err as Error).message }, 'signed-in apps unavailable')
  return reply.status(503).send({ error: 'unavailable', message: 'Signed-in apps cannot be read right now.' })
}

export async function mcpConnectionsRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', personOnly)

  fastify.get('/', {
    ...open('self'),
    schema: {
      description: 'Your signed-in AI apps (MCP browser sign-ins): name (unverified), permissions mode, protected actions, dates, last use.',
      tags: ['oauth'],
      response: {
        200: { type: 'object', properties: { data: { type: 'array', items: connectionSchema }, total: { type: 'integer' } } },
        401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFoundResponseSchema, 503: serviceUnavailableResponseSchema,
      },
    },
  }, async (request, reply) => {
    try {
      const data = await listConnections(request.userContext!.id)
      return { data, total: data.length }
    } catch (err) {
      return hydraDown(err, reply)
    }
  })

  fastify.delete('/', {
    ...open('self'),
    schema: {
      description: 'Disconnect every AI app you signed in with a browser: their tokens stop within 30 seconds and their registrations are deleted.',
      tags: ['oauth'],
      response: { 204: { type: 'null' }, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFoundResponseSchema, 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    const me = request.userContext!.id
    let clients: string[]
    try {
      clients = await revokeAllConnections(me)
    } catch (err) {
      return hydraDown(err, reply)
    }
    oauthAudit('mcp.oauth.revoked_all', { actor: auditActor(request), targetId: me, targetType: 'user', details: { subject: me, clients: clients.length, via: 'self' } })
    return reply.status(204).send()
  })

  fastify.delete('/:clientId', {
    ...open('self'),
    schema: {
      description: 'Disconnect one of your signed-in AI apps: its tokens stop within 30 seconds and its registration is deleted.',
      tags: ['oauth'],
      params: { type: 'object', required: ['clientId'], properties: { clientId: { type: 'string', minLength: 1, maxLength: 256 } } },
      response: { 204: { type: 'null' }, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFoundResponseSchema, 503: serviceUnavailableResponseSchema },
    },
  }, async (request: FastifyRequest<{ Params: { clientId: string } }>, reply) => {
    const me = request.userContext!.id
    let revoked: boolean
    try {
      revoked = await revokeConnection(me, request.params.clientId)
    } catch (err) {
      return hydraDown(err, reply)
    }
    if (!revoked) return reply.status(404).send({ error: 'Not Found', message: 'No such signed-in app.' })
    oauthAudit('mcp.oauth.revoked', { actor: auditActor(request), targetId: request.params.clientId, details: { subject: me } })
    return reply.status(204).send()
  })
}

/**
 * POST /api/me/mcp/step-up-requests — a key or a signed-in assistant asks for a link to refresh the
 * second factor IT stands on for protected actions (step-up-refresh.ts). The credential asks for
 * itself: a delegated caller only (the delegation gate lets this one write through).
 */
export async function stepUpRequestRoutes(fastify: FastifyInstance) {
  fastify.post('/', {
    ...open('self'),
    schema: {
      description:
        'For an AI assistant acting through a personal key or a browser sign-in: a single-use link (10 minutes) that its ' +
        'holder opens to prove a second factor again, renewing the protected-actions window of THIS credential. 400 ' +
        'not_delegated from a browser session; 409 protected_actions_not_allowed when the key or the sign-in was given none ' +
        '(reconnect / new key); 403 protected_actions_off | mcp_disabled; 429 with Retry-After past 5 links per 10 minutes.',
      tags: ['oauth'],
      response: {
        201: { type: 'object', properties: { url: { type: 'string' }, expiresAt: { type: 'string' } } },
        400: flowError, 401: unauthorizedResponseSchema, 403: flowError, 409: flowError, 429: flowError, 503: flowError,
      },
    },
  }, async (request, reply) => {
    const uc = request.userContext
    const d = uc?.delegation
    if (uc?.authVia !== 'delegated' || !d) {
      return reply.status(400).send({ error: 'not_delegated', message: 'Ask from your assistant: the link refreshes the key or sign-in that asks for it.' })
    }
    try {
      const link = await createStepUpRequest({
        subject: uc.id,
        clientId: d.clientId,
        kind: d.kind,
        stepUpActions: d.kind === 'oauth' ? d.stepUpActions === true : d.keyStepUpActions !== false,
      })
      return reply.status(201).header('cache-control', 'no-store').send(link)
    } catch (err) {
      return flowFailed(err, reply)
    }
  })
}

export async function mcpConnectionsAdminRoutes(fastify: FastifyInstance) {
  fastify.delete('/users/:id/mcp-connections', {
    ...needs('sessions:revoke'),
    schema: {
      description: "Disconnect every AI app a person signed in with a browser (MCP). Also done by revoking all their sessions. Needs sessions:revoke.",
      tags: ['oauth'],
      params: { type: 'object', required: ['id'], properties: { id: { type: 'string', minLength: 1, maxLength: 128 } } },
      response: { 204: { type: 'null' }, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 503: serviceUnavailableResponseSchema },
    },
  }, async (request: FastifyRequest<{ Params: { id: string } }>, reply) => {
    let clients: string[]
    try {
      clients = await revokeAllConnections(request.params.id)
    } catch (err) {
      return hydraDown(err, reply)
    }
    oauthAudit('mcp.oauth.revoked_all', { actor: auditActor(request), targetId: request.params.id, targetType: 'user', details: { subject: request.params.id, clients: clients.length } })
    return reply.status(204).send()
  })
}
