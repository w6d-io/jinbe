import { FastifyRequest, FastifyReply } from 'fastify'
import { holdsInJinbe } from '../authz/opa.js'
import { enforcing } from '../policy/declared-routes.js'
import { denyAudit } from '../audit/deny.js'

/**
 * Requires a permission ACROSS the platform, asked of OPA: what the caller holds in jinbe, global
 * roles included — the resolution the gateway decides with.
 *
 * For the surfaces that are not about one organisation: listing every organisation, reading the
 * audit trail, handing out a group. `admin:read` admits `admin.organisation:read` (an ancestor covers
 * its refinements), and `*` admits everything.
 *
 * It refuses rather than narrowing: a screen that asked for everything and received less would have
 * no way to tell a short answer from a complete one.
 */
export function requirePlatformPermission(required: string) {
  // Marked so the published route table is READ OFF the guard rather than written beside it.
  return enforcing(async function (request: FastifyRequest, reply: FastifyReply) {
    const email = request.userContext?.email
    if (!request.userContext?.id || request.userContext.id === 'unknown' || !email || email === 'unknown') {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    }

    let permitted: boolean
    try {
      permitted = await holdsInJinbe(email, required)
    } catch (err) {
      // "Does not hold it" and "I could not tell" are opposite facts. A 403 here would read as a
      // missing right rather than as an engine nobody could ask.
      request.log.warn({ email, required, err: (err as Error).message }, '[platform] OPA could not be asked')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    }

    if (!permitted) {
      denyAudit(request, `missing_permission:${required}`)
      return reply.status(403).send({
        error: 'Forbidden',
        message: `This needs ${required}.`,
      })
    }
  }, required)
}
