import type { FastifyInstance, FastifyRequest } from 'fastify'
import { z } from 'zod'
import { sitesConfig } from './config.js'
import { handle, nameOf, parse } from './http.js'
import { accessReason, getLogo, publicLoginByHost, publicLoginByName } from './login.js'

/**
 * /api/public/sites — what login-ui needs about a site before anyone is signed in (site-ux §11.2).
 *
 * No session gate (listed in require-auth PUBLIC_ROUTES): these only say what the site's own
 * address already shows — name, logo, colour, welcome line, help link, 2FA bar. Exact match only,
 * nothing lists sites, every route is rate limited per IP. The one route that is about a person,
 * access-reason, takes that person's own Kratos session cookie and answers one word.
 */

const hostParams = z.object({ host: z.string().min(1).max(253).regex(/^[A-Za-z0-9.-]+$/) })
const CACHE = 'public, max-age=60'

export async function publicSitesRoutes(fastify: FastifyInstance) {
  const limit = { rateLimit: { max: sitesConfig().SITES_PUBLIC_RATE_LIMIT, timeWindow: '1 minute' } }
  const doc = (description: string) => ({ schema: { description, tags: ['sites'] }, config: limit })

  fastify.get('/by-host/:host', doc('Login branding and 2FA bar of the site served on exactly this host; 404 otherwise'),
    handle(async (request, reply) => {
      const out = await publicLoginByHost(parse(hostParams, request.params).host)
      reply.header('cache-control', CACHE)
      return out
    }))

  fastify.get('/:name/login', doc('Login branding and 2FA bar of one site, by name'), handle(async (request, reply) => {
    const out = await publicLoginByName(nameOf(request))
    reply.header('cache-control', CACHE)
    return out
  }))

  fastify.get('/:name/logo', doc('The site login-page logo (PNG or WebP)'), handle(async (request, reply) => {
    const logo = await getLogo(nameOf(request))
    return reply
      .header('content-type', logo.type)
      .header('cache-control', CACHE)
      .header('etag', `"${logo.etag}"`)
      .header('x-content-type-options', 'nosniff')
      .header('content-security-policy', "default-src 'none'; sandbox")
      .send(Buffer.from(logo.data, 'base64'))
  }))

  fastify.get('/:name/access-reason', doc('Why the signed-in visitor (own Kratos session cookie) was refused GET <url> on this site: {reason: needs_2fa|forbidden|ok|not_found, minAal}'),
    handle(async (request: FastifyRequest, reply) => {
      const out = await accessReason(nameOf(request), (request.query as { url?: unknown } | undefined)?.url, request.headers.cookie)
      reply.header('cache-control', 'no-store')
      return out
    }))
}
