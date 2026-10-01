import type { KratosBindingsResponse } from './rbac.service.js'

/**
 * Addresses in the policy data, case-safe while the stores move to lowercase.
 *
 * jinbe keys the RBAC bindings on an identity's address AS TYPED (traits.email) and the gateway asks
 * OPA with that same spelling. Until the policy compares addresses without case, the bindings carry
 * each address-keyed map also under its lowercase key (never replacing a real one).
 *
 * Only the OPAL feeds read these; displays keep one row per identity.
 */

type AddressMaps = Pick<KratosBindingsResponse, 'group_membership' | 'user_organizations' | 'user_organization_primary' | 'org_assignments' | 'direct'>

function withLowercase<T>(map: Record<string, T>): Record<string, T> {
  const out: Record<string, T> = { ...map }
  for (const [address, value] of Object.entries(map)) {
    const lower = address.toLowerCase()
    if (!(lower in out)) out[lower] = value
  }
  return out
}

export function bindingsWithLowercaseKeys<B extends AddressMaps>(bindings: B): B {
  return {
    ...bindings,
    group_membership: withLowercase(bindings.group_membership),
    user_organizations: withLowercase(bindings.user_organizations),
    user_organization_primary: withLowercase(bindings.user_organization_primary),
    org_assignments: withLowercase(bindings.org_assignments),
    direct: withLowercase(bindings.direct),
  }
}
