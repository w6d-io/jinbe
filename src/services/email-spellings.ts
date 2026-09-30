import type { KratosBindingsResponse } from './rbac.service.js'

/**
 * Addresses in the policy data, case-safe while the stores move to lowercase.
 *
 * jinbe keys the RBAC bindings on an identity's address AS TYPED (traits.email) and the gateway asks
 * OPA with that same spelling, while the org-admin roster is now stored lowercased (and was typed by
 * hand before). Until the policy compares addresses without case (opal-policies rbac-explain.patch),
 * the feeds carry every spelling, so no lookup changes answer whichever spelling asks:
 *
 *   bindings — each address-keyed map also under its lowercase key (never replacing a real one);
 *   roster   — each entry as stored, lowercased, and as every identity that spells it spells it.
 *
 * Only the OPAL feeds read these; displays keep one row per identity.
 */

type AddressMaps = Pick<KratosBindingsResponse, 'group_membership' | 'user_organizations' | 'user_organization_primary'>

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
  }
}

/** The rosters with every spelling the policy may be asked with. */
export function rosterForPolicy(stored: Record<string, readonly string[]>, identityAddresses: Iterable<string>): Record<string, string[]> {
  const spellings = new Map<string, Set<string>>()
  for (const address of identityAddresses) {
    const lower = address.toLowerCase()
    if (!spellings.has(lower)) spellings.set(lower, new Set())
    spellings.get(lower)!.add(address)
  }
  const out: Record<string, string[]> = {}
  for (const [org, entries] of Object.entries(stored)) {
    const all = new Set<string>()
    for (const entry of entries) {
      const lower = entry.trim().toLowerCase()
      if (!lower) continue
      all.add(entry)
      all.add(lower)
      for (const s of spellings.get(lower) ?? []) all.add(s)
    }
    if (all.size > 0) out[org] = [...all].sort()
  }
  return out
}
