import { createHmac, randomBytes } from 'node:crypto'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { env } from '../config/index.js'
import { clientIp } from '../utils/client-ip.js'
import { KratosSessionService } from '../services/kratos-session.service.js'

/**
 * Rate limits of the login/consent provider (/api/public/oauth2/*).
 *
 * Every call comes from login-ui's pods, so a per-address limit on the socket would be ONE bucket for
 * everybody signing in: one abuser would throttle every sign-in. Each caller is keyed on, in order:
 *   1. the visitor's address, when a trusted hop forwarded it (login-ui passes on the X-Forwarded-For
 *      it received, or Envoy's x-envoy-external-address — utils/client-ip.ts decides what is trusted);
 *   2. else the visitor's Kratos session cookie (an HMAC under a per-process key, never the cookie);
 *   3. else the socket address.
 * A made-up cookie per request escapes (2), so a per-replica ceiling over all callers stays as the
 * backstop (MCP_OAUTH_PROVIDER_CEILING a minute).
 */

export const PER_CALLER_PER_MINUTE = 120
const WINDOW_MS = 60_000
const hmacKey = randomBytes(32)

export function providerRateKey(request: FastifyRequest): string {
  const ip = clientIp(request)
  const peer = request.socket?.remoteAddress
  if (ip && peer && ip !== peer) return `ip:${ip}`
  const cookie = KratosSessionService.extractSessionCookie(request.headers.cookie)
  if (cookie) return `sess:${createHmac('sha256', hmacKey).update(cookie).digest('base64url')}`
  return `peer:${ip || peer || 'unknown'}`
}

let window = { start: 0, count: 0 }

/** Test seam. */
export function resetProviderCeiling(): void {
  window = { start: 0, count: 0 }
}

/** onRequest: 429 once this replica has answered the ceiling's worth of provider calls this minute. */
export async function providerCeiling(_request: FastifyRequest, reply: FastifyReply) {
  const now = Date.now()
  if (now - window.start >= WINDOW_MS) window = { start: now, count: 0 }
  window.count++
  if (window.count > env.MCP_OAUTH_PROVIDER_CEILING) {
    const retry = Math.max(1, Math.ceil((window.start + WINDOW_MS - now) / 1000))
    return reply.status(429).header('Retry-After', String(retry)).send({ error: 'rate_limited', message: 'Signing in is busy right now. Try again in a moment.' })
  }
}
