import type { FastifyRequest } from 'fastify'
import { env } from '../config/index.js'
import { opaService } from './opa.service.js'

/**
 * The organisations a caller may act on, from whichever authority the deployment named.
 *
 * One place knows the rule, because the alternative is every caller deciding for itself and the
 * setting meaning different things in different corners. `local` asks this service own model, which
 * the console administers. `claim` reads the verified token: the deployment has delegated who
 * belongs where to whoever issues it, so asking anything else would be second-guessing the
 * authority it named.
 *
 * That delegation is the whole point of the setting. A deployment that reads organisations from the
 * token deliberately never populates the local model — so falling back to it when the claim is
 * empty would turn "this person belongs to nothing" into "ask an administrator to add you", which
 * is advice nobody can act on. An empty answer is an answer.
 *
 * Whether the caller may *administer* those organisations is a separate question, and it stays
 * where it was: the roles and permissions this service resolves for the route being called.
 */
export async function callerOrganisations(
  request: FastifyRequest,
  email: string | undefined,
): Promise<string[]> {
  if (env.ORGANISATION_SOURCE === 'claim') {
    return [...(request.userContext?.organisations ?? [])]
  }
  // The address is passed in rather than read here: a caller can be identified through a session or
  // through a token, and which one answered is already settled where this is called from. Resolving
  // it twice is how the two answers drift.
  if (!email) return []
  return opaService.manageableOrgs(email)
}

/** How the answer was reached, for the callers that report their scope. */
export function callerOrganisationsScope(): 'delegated' | 'claim' {
  return env.ORGANISATION_SOURCE === 'claim' ? 'claim' : 'delegated'
}
