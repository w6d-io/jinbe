import { timingSafeEqual } from 'node:crypto'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { env } from '../config/env.js'

// OPAL's server answers a client's config request with a redirect to the manifest, adding the
// client's token as ?token= (a bearer header does not survive the cross-host redirect). Every data
// fetch after that sends it as a bearer header, because the manifest tells the client to.
const MANIFEST = /\/opal-datasource$/

function same(given: string | undefined, expected: string): boolean {
  if (!given) return false
  const a = Buffer.from(given)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}

function presented(request: FastifyRequest): Array<string | undefined> {
  const header = request.headers.authorization
  const tokens = [header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined]
  if (MANIFEST.test(request.url.split('?')[0])) {
    tokens.push((request.query as { token?: string } | undefined)?.token)
  }
  return tokens
}

/** Only an OPAL client may read the policy data these routes publish. Unset token: nobody may. */
export async function requireOpalClient(request: FastifyRequest, reply: FastifyReply) {
  const expected = env.OPAL_CLIENT_TOKEN
  if (expected && presented(request).some((token) => same(token, expected))) return
  return reply.status(401).send({ error: 'Unauthorized', message: 'OPAL client token required' })
}

/** Keeps the manifest's ?token= out of request logs. */
export function redactQueryToken(url: unknown): unknown {
  return typeof url === 'string' ? url.replace(/([?&]token=)[^&#]*/g, '$1[redacted]') : url
}
