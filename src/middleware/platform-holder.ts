import type { FastifyRequest } from 'fastify'
import { rights } from '../authz/opa.js'
import { grants, isCatalogPermission } from '../policy/catalog.js'

/**
 * Whether the caller holds the route's declared catalogue permission ACROSS THE PLATFORM — a staff
 * role bound under `global` (staff-rbac-proposal §1 rule c: the same name held globally or for one
 * org). Such a holder passes an org-scoped route's gate in every organisation; the org layer (member,
 * roster admin, org grants) still decides everybody else.
 *
 * False when the route declares no catalogue permission, so a gate mounted without a declaration
 * never widens. Throws when OPA cannot be asked: the gates turn that into a 503.
 */
export async function holdsDeclaredPermissionGlobally(request: FastifyRequest): Promise<boolean> {
  const declared = request.routeOptions?.config?.permission
  const email = request.userContext?.email
  if (!declared || !isCatalogPermission(declared) || !email || email === 'unknown') return false
  // A delegated caller's token is narrowed by the delegation gate before any route gate; the person
  // behind it is asked here exactly as for a session.
  return grants((await rights(email)).permissions, declared)
}
