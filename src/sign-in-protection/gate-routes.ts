import type { FastifyInstance, FastifyRequest } from 'fastify'
import http from 'node:http'
import https from 'node:https'
import type { IncomingHttpHeaders } from 'node:http'
import { env } from '../config/index.js'
import { gateRefusalBody, gateSubmit, hashForLog, parseSubmitBody, submitToken, type GateFlow } from './gate.js'
import { clientIp } from '../utils/client-ip.js'

/**
 * POST /api/public/sign-in-protection/gate/self-service/:flow — the sign-in gate's front door (gate.ts).
 *
 * Oathkeeper's `selfservice-gate` rule (bootstrap build-rules.ts) sends every
 * POST /self-service/{login,registration,recovery,verification,settings} on the sign-in domain here, with the
 * original path appended, query and headers untouched. A submit the gate allows is replayed to
 * Kratos public byte for byte and Kratos' answer (status, Set-Cookie, redirect, body) goes back as
 * is; a refused one gets a 403/429 JSON error and never reaches Kratos.
 *
 * Public on purpose, like Kratos behind it: reaching it directly is just another way through the gate.
 */

export const GATE_TOKEN_HEADER = 'x-captcha-token'
const FLOWS = new Set<GateFlow>(['login', 'registration', 'recovery', 'verification', 'settings'])
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'host'])
const MAX_BODY = 64 * 1024
const KRATOS_TIMEOUT_MS = 15_000

/** Request headers for Kratos: the browser's, minus hop-by-hop ones and the bot-check token. */
function forwardHeaders(headers: IncomingHttpHeaders, body: Buffer): http.OutgoingHttpHeaders {
  const out: http.OutgoingHttpHeaders = {}
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined || HOP_BY_HOP.has(k) || k === GATE_TOKEN_HEADER) continue
    out[k] = v
  }
  // Kratos sees the sign-in host, as it did when Oathkeeper proxied to it directly (preserve_host).
  if (headers.host) out.host = headers.host
  out['content-length'] = String(body.length)
  return out
}

/**
 * The live Kratos session the submit carries (second factor, refresh, settings), with its email. The
 * session cookie was already validated by extractIdentity (request.validatedSession); an API flow's
 * X-Session-Token is asked of Kratos here.
 */
async function kratosSession(request: FastifyRequest, fetchImpl: typeof fetch): Promise<{ email: string | null } | null> {
  if (request.validatedSession) return { email: request.validatedSession.email || null }
  const token = request.headers['x-session-token']
  if (typeof token !== 'string' || !token) return null
  try {
    const res = await fetchImpl(`${env.KRATOS_PUBLIC_URL.replace(/\/+$/, '')}/sessions/whoami`, {
      headers: { 'x-session-token': token, accept: 'application/json' },
      signal: AbortSignal.timeout(2000),
    })
    if (!res.ok) return null
    const body = (await res.json()) as { identity?: { traits?: { email?: unknown } } }
    const email = body.identity?.traits?.email
    return { email: typeof email === 'string' ? email : null }
  } catch {
    return null
  }
}

/** The Kratos flow id from `?flow=`, when it looks like one. */
function flowIdOf(query: unknown): string | null {
  const v = (query as Record<string, unknown> | null)?.flow
  return typeof v === 'string' && /^[A-Za-z0-9-]{8,64}$/.test(v) ? v : null
}

export interface GateRouteOptions {
  /** Test seam: the provider and whoami calls. */
  fetchImpl?: typeof fetch
  /** Test seam: where allowed submits go (defaults to KRATOS_PUBLIC_URL). */
  kratosUrl?: string
}

export async function signInGateRoutes(fastify: FastifyInstance, opts: GateRouteOptions = {}) {
  const fetchImpl = opts.fetchImpl ?? fetch
  // The body is forwarded as it came: read it raw, whatever its type (this plugin's scope only).
  fastify.removeAllContentTypeParsers()
  fastify.addContentTypeParser('*', { parseAs: 'buffer', bodyLimit: MAX_BODY }, (_req, body, done) => done(null, body))

  fastify.post<{ Params: { flow: string } }>('/self-service/:flow', {
    config: {
      access: 'public',
      rateLimit: {
        max: 120,
        timeWindow: '1 minute',
        // The visitor's address as the edge saw it (utils/client-ip.ts), never the first X-Forwarded-For entry.
        keyGenerator: (request: FastifyRequest) => clientIp(request),
      },
    },
    schema: {
      description:
        'The sign-in gate, called by the gateway with the original Kratos path appended: judges a self-service submit ' +
        '(bot-check token in X-Captcha-Token, code-sending limits) and passes it on to Kratos, or answers 403/429.',
      tags: ['sign-in-protection'],
      hide: true,
    },
  }, async (request, reply) => {
    const flow = request.params.flow as GateFlow
    if (!FLOWS.has(flow)) return reply.status(404).send({ error: { code: 404, status: 'Not Found', message: 'Not Found' } })

    const body = Buffer.isBuffer(request.body) ? request.body : Buffer.alloc(0)
    const ip = clientIp(request)
    const tokenHeader = request.headers[GATE_TOKEN_HEADER]
    const fields = parseSubmitBody(request.headers['content-type'], body)
    const decision = await gateSubmit({
      flow,
      flowId: flowIdOf(request.query),
      fields,
      token: submitToken(typeof tokenHeader === 'string' && tokenHeader ? tokenHeader : null, fields),
      ip,
      session: () => kratosSession(request, fetchImpl),
    }, fetchImpl)

    if (!decision.allow) {
      // Hashes only: the address and the IP never reach the log.
      request.log.info({ flow, step: decision.step, result: decision.result, ip: ip ? hashForLog(ip) : null }, 'Sign-in gate refused a self-service submit')
      if (decision.retryAfter !== undefined) reply.header('retry-after', String(decision.retryAfter))
      reply.header('cache-control', 'no-store')
      return reply.status(decision.status).send(gateRefusalBody(decision))
    }

    const target = new URL(request.url.replace(/^.*?\/self-service\//, '/self-service/'), opts.kratosUrl ?? env.KRATOS_PUBLIC_URL)
    const client = target.protocol === 'https:' ? https : http
    reply.hijack()
    await new Promise<void>((resolve) => {
      const upstream = client.request(target, { method: 'POST', headers: forwardHeaders(request.headers, body), timeout: KRATOS_TIMEOUT_MS }, (res) => {
        const raw: string[] = []
        for (let i = 0; i < res.rawHeaders.length; i += 2) {
          if (!HOP_BY_HOP.has(res.rawHeaders[i].toLowerCase()) || res.rawHeaders[i].toLowerCase() === 'content-length') {
            raw.push(res.rawHeaders[i], res.rawHeaders[i + 1])
          }
        }
        reply.raw.writeHead(res.statusCode ?? 502, raw)
        res.pipe(reply.raw)
        res.on('end', resolve)
        res.on('error', () => { reply.raw.destroy(); resolve() })
      })
      const fail = (err: Error) => {
        request.log.warn({ flow, err: err.message }, 'Sign-in gate could not reach Kratos')
        if (!reply.raw.headersSent) {
          reply.raw.writeHead(502, { 'content-type': 'application/json', 'cache-control': 'no-store' })
          reply.raw.end(JSON.stringify({ error: { code: 502, status: 'Bad Gateway', message: 'Sign-in is unavailable right now. Please try again in a minute.' } }))
        } else {
          reply.raw.destroy()
        }
        resolve()
      }
      upstream.on('timeout', () => upstream.destroy(new Error('timeout')))
      upstream.on('error', fail)
      upstream.end(body)
    })
  })
}
