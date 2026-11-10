import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { open } from '../policy/route-access.js'
import { KratosSessionService, kratosSessionService } from '../services/kratos-session.service.js'
import { checkImpersonation } from './check.js'
import { impersonationEnabled, impersonationToken } from './service.js'
import { siteOriginHost } from './site-origins.js'

/**
 * `/sessions/whoami` on the auth host, for a browser that carries the impersonation cookie.
 *
 * Site front ends ask the auth host who is signed in, cross-origin, with the browser's cookies. The
 * gateway already serves an impersonating administrator the site as the user; without this the page
 * around it still greeted the administrator. With impersonation on, the gateway sends the auth
 * host's `GET /sessions/whoami` here (built-in rule `impersonation-whoami`, bootstrap/build-rules.ts)
 * — every one of them, so a request without the impersonation cookie costs one call to Kratos and
 * nothing else (the server's identity extraction skips this path: WHOAMI_RELAY_PATH).
 *
 * The answer is Kratos' OWN, relayed unchanged (status and body), unless both hold:
 *   - the request's Origin is a site's (site-origins.ts) — never the console, the login UI or any
 *     platform host, never a request without an Origin (a navigation, a server-side caller);
 *   - the gateway's check passes for a GET (check.ts: live grant, the administrator's own valid aal2
 *     session, still permitted, the user still eligible).
 * Then it is the impersonated session, the same body the gateway reads. Any doubt — a refusal, a
 * lookup that failed — is answered with Kratos' answer, never with the impersonated one.
 *
 * Reads only: no cookie is set, nothing is written but the sampled `impersonation.used` trail.
 *
 * CORS belongs to the edge (the route's CORS filter): whatever this service's own CORS setup added
 * is removed here, so the browser never sees the header twice.
 */

const one = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v) || undefined

/** Every Access-Control-* header this service may have set on the reply (plugins/cors.ts). */
async function withoutOwnCors<T>(_request: FastifyRequest, reply: FastifyReply, payload: T): Promise<T> {
  for (const name of Object.keys(reply.getHeaders())) {
    if (name.toLowerCase().startsWith('access-control-')) reply.removeHeader(name)
  }
  // Set last: the CORS plugin writes its own `Vary: Origin`.
  reply.header('Vary', 'Origin, Cookie')
  return payload
}

/** The impersonated session for this request, or null: anything short of a clear yes. */
async function impersonated(request: FastifyRequest) {
  // Every browser's whoami on the auth host comes through here, nearly all of them without the
  // impersonation cookie: those go straight to Kratos, with no lookup of sites or grants.
  if (!impersonationEnabled() || !impersonationToken(request.headers.cookie)) return null
  const host = await siteOriginHost(request.headers.origin)
  if (!host) return null
  try {
    const result = await checkImpersonation({ method: 'GET', cookieHeader: request.headers.cookie, host })
    if (result.ok) return result.session
    request.log.debug({ reason: result.reason, grantId: result.grant?.id, host }, '[impersonation] whoami answered by Kratos')
    return null
  } catch (err) {
    request.log.warn({ err: (err as Error).message, host }, '[impersonation] whoami check failed; answered by Kratos')
    return null
  }
}

async function whoamiHandler(request: FastifyRequest, reply: FastifyReply) {
  reply.header('Cache-Control', 'no-store')
  const session = await impersonated(request)
  if (session) return reply.header('X-Kratos-Authenticated-Identity-Id', session.identity.id).send(session)

  const query = request.url.includes('?') ? request.url.slice(request.url.indexOf('?')) : ''
  let answer: Awaited<ReturnType<typeof kratosSessionService.whoamiRaw>>
  try {
    answer = await kratosSessionService.whoamiRaw({
      // Kratos' own cookies only: the impersonation cookie and the site's cookies are not its business.
      cookie: KratosSessionService.extractSessionCookie(request.headers.cookie),
      sessionToken: one(request.headers['x-session-token']),
      authorization: one(request.headers.authorization),
    }, query)
  } catch (err) {
    request.log.warn({ err: (err as Error).message }, '[impersonation] whoami: Kratos unreachable')
    return reply.status(503).send({ error: 'identity_service_unavailable', message: 'The identity service could not be reached. Please try again.' })
  }
  if (answer.identityId) reply.header('X-Kratos-Authenticated-Identity-Id', answer.identityId)
  return reply.status(answer.status).header('Content-Type', answer.contentType ?? 'application/json').send(answer.body)
}

/** Registered under /api/public/impersonation. */
export async function impersonationWhoamiRoutes(fastify: FastifyInstance) {
  fastify.get('/whoami', {
    // No gateway row: the edge routes the auth host's /sessions/whoami here itself. No rate limit of
    // its own either: fronts poll whoami, and the edge is the one caller for all of them.
    config: { ...open('machine').config, rateLimit: false },
    onSend: withoutOwnCors,
    schema: {
      description:
        "The auth host's /sessions/whoami while the browser carries the impersonation cookie (routed here by the edge): " +
        "Kratos' own answer relayed unchanged, or — for a site's page, while the impersonation is valid — the impersonated " +
        'session. Never cacheable; sets no cookie.',
      tags: ['public'],
      // No response schema: either Kratos' body or the identity as Kratos returns it.
    },
  }, whoamiHandler)
}
