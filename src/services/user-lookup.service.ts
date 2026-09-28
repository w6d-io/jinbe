import type { KratosIdentity } from '../schemas/admin.schema.js'
import { rights } from '../authz/opa.js'
import { KratosApiError, kratosService, MFA_METHODS } from './kratos.service.js'
import { organisationsOf } from './org-membership.service.js'

/**
 * "Who is this?" for a box somebody types into: a Kratos identity id, a whole address, or the start
 * of one — answered as-you-type without walking the directory.
 *
 *   id      — a pasted UUID: one GET by id.
 *   email   — a whole address: Kratos's exact `credentials_identifier` match.
 *   prefix  — anything else: Kratos's own prefix match on the login identifier, one bounded query.
 *   contains — only when the prefix finds nobody: the substring search over the cached directory map
 *              (email + name), so a fragment from the middle of an address or a name still lands.
 *
 * Each hit carries what the checker and the people screen show on the card: groups as the engine
 * resolves them, organisations, and whether a second factor is enrolled. A part that cannot be
 * read is marked unknown on that hit, never answered as "none".
 */

export type LookupMatch = 'id' | 'email' | 'prefix' | 'contains' | 'none'

export interface LookupHit {
  id: string
  email: string
  name: string | null
  active: boolean
  /** null when the engine could not be asked: unknown, not "no groups". */
  groups: string[] | null
  organizations: string[] | null
  mfa: boolean | null
}

export interface LookupAnswer {
  match: LookupMatch
  data: LookupHit[]
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export const LOOKUP_MAX = 10

export function classify(q: string): 'id' | 'email' | 'prefix' {
  if (UUID.test(q)) return 'id'
  if (EMAIL.test(q)) return 'email'
  return 'prefix'
}

async function describe(identity: KratosIdentity, mfa: boolean | null): Promise<LookupHit> {
  const email = (identity.traits?.email as string | undefined) ?? ''
  const [groups, organizations] = await Promise.all([
    email ? rights(email).then((r) => r.groups, () => null) : Promise.resolve([] as string[]),
    organisationsOf(identity).catch(() => null),
  ])
  return {
    id: identity.id,
    email,
    name: (identity.traits?.name as string | undefined) ?? null,
    active: identity.state === 'active',
    groups,
    organizations,
    mfa,
  }
}

/** Fetched with its second factors, so 2FA is read from the same answer. */
const withMfa = (identity: KratosIdentity) => describe(identity, kratosService.mfaFromCredentials(identity.credentials))

async function byId(id: string): Promise<KratosIdentity | null> {
  try {
    return await kratosService.getIdentityWithSecondFactors(id)
  } catch (err) {
    if (err instanceof KratosApiError && err.statusCode === 404) return null
    throw err
  }
}

export async function lookupUsers(raw: string, limit = LOOKUP_MAX): Promise<LookupAnswer> {
  const q = raw.trim()
  const max = Math.min(Math.max(limit, 1), LOOKUP_MAX)
  if (!q) return { match: 'none', data: [] }

  const kind = classify(q)
  if (kind === 'id') {
    const identity = await byId(q.toLowerCase())
    return identity ? { match: 'id', data: [await withMfa(identity)] } : { match: 'none', data: [] }
  }

  if (kind === 'email') {
    const exact = await kratosService.listIdentities(1, undefined, q, [...MFA_METHODS])
    if (exact.identities[0]) return { match: 'email', data: [await withMfa(exact.identities[0])] }
  }

  const prefixed = await kratosService.listIdentitiesByIdentifierPrefix(q, max)
  if (prefixed && prefixed.length > 0) {
    return { match: 'prefix', data: await Promise.all(prefixed.map(withMfa)) }
  }

  // Nobody starts with it (or this Kratos has no prefix match): the substring search over the
  // cached map. Too short a fragment matches half the directory and tells nobody anything.
  if (q.length < 3) return { match: 'none', data: [] }
  const contained = await kratosService.searchIdentities(q, max)
  if (contained.length === 0) return { match: 'none', data: [] }
  const hits = await Promise.all(
    contained.map(async (row) => {
      const identity = await byId(row.id)
      return identity ? withMfa(identity) : null
    }),
  )
  return { match: 'contains', data: hits.filter((h): h is LookupHit => h !== null) }
}
