import type { FastifyReply, FastifyRequest } from 'fastify'
import { env } from '../config/index.js'
import { denyAudit } from '../audit/deny.js'

/**
 * The only credential /api/internal/* takes: an in-cluster service's projected ServiceAccount token,
 * verified by the API server (TokenReview, K8S_SA_AUTH_ENABLED) and listed in
 * INTERNAL_API_ALLOWED_SUBJECTS (`namespace:serviceaccount`, `namespace:*`).
 *
 * "Oathkeeper does not route this prefix" was the whole guard, and NetworkPolicy is not enforced: any
 * pod could resolve any client_id to its organization and scopes, and so could any signed-in person,
 * whose session passed the global gate. A session, a user's bearer token, a delegated token — none of
 * them is an in-cluster caller, so none of them gets in. An empty list refuses everyone.
 */
export async function requireInternalCaller(request: FastifyRequest, reply: FastifyReply) {
  const machine = request.userContext?.authVia === 'machine' ? request.machine : undefined
  const allowed = env.INTERNAL_API_ALLOWED_SUBJECTS
  const ok =
    !!machine &&
    (allowed.includes(`${machine.namespace}:${machine.serviceAccount}`) || allowed.includes(`${machine.namespace}:*`))
  if (ok) return
  denyAudit(request, machine ? 'internal_caller_not_allowed' : 'internal_caller_required')
  return reply.status(machine ? 403 : 401).send({
    error: machine ? 'Forbidden' : 'Unauthorized',
    message: 'Internal routes take an allowed in-cluster ServiceAccount token, and nothing else.',
  })
}
