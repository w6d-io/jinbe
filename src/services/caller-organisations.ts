import type { FastifyRequest } from 'fastify'
import { env } from '../config/index.js'
import { organisationsForSubject } from './organisation-store.js'

/**
 * The organisations a caller may act on, from whichever authority the deployment named.
 *
 * One place knows the rule, because the alternative is every caller deciding for itself and the
 * setting meaning different things in different corners. `local` infers the set from group
 * memberships, as this service has always done. `directory` reads the records this service owns,
 * which is the only source that can also answer about a subject the caller is not. `claim` reads
 * the verified token: the deployment has delegated who belongs where to whoever issues it, so
 * asking anything else would be second-guessing the authority it named.
 *
 * That delegation is the whole point of the setting. A deployment that reads organisations from the
 * token deliberately never populates the local model — so falling back to it when the claim is
 * empty would turn "this person belongs to nothing" into "ask an administrator to add you", which
 * is advice nobody can act on. An empty answer is an answer.
 *
 * Whether the caller may *administer* those organisations is a separate question, and it stays
 * where it was: the roles and permissions this service resolves for the route being called.
 */
export async function callerOrganisations(request: FastifyRequest): Promise<string[]> {
  if (env.ORGANISATION_SOURCE === 'claim') {
    return [...(request.userContext?.organisations ?? [])]
  }

  // The subject, never the address: an address is a trait its owner can change, and a changed one
  // must not move an entitlement — nor a reused one inherit the last holder's. A store that cannot
  // answer throws rather than answering nothing, because "cannot tell" and "belongs to nothing" are
  // opposite facts and only one of them may authorise.
  const subject = request.userContext?.id
  if (!subject) return []
  // There was a third source, `local`, and it was the DEFAULT: it asked an engine for
  // `data.rbac.delegation.manageable_orgs`, a path that stopped existing when the model became
  // `strada.authz`. It answered nothing, so it scoped every caller to no organisation at all — and
  // being the default, any deployment that did not set this variable fell into it. Removed, and the
  // default is now the directory that actually holds them.
  return organisationsForSubject(request.userContext?.id ?? '')
}

/**
 * How the answer was reached, for the callers that report their scope.
 *
 * `claim` is the one a client has to know about: it is the case where nothing here can be changed
 * to alter the answer, so a screen showing an empty list must say where to go instead of advising
 * something nobody can act on.
 */
export function callerOrganisationsScope(): 'delegated' | 'claim' {
  return env.ORGANISATION_SOURCE === 'claim' ? 'claim' : 'delegated'
}
