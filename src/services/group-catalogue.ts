import { redisRbacRepository } from './redis-rbac.repository.js'
import { JINBE } from '../policy/roles.js'

/**
 * The groups jinbe publishes to OPA (Redis → OPAL → `data.bindings.groups`), read for the screens and
 * the write path — never to decide who may do what, which is OPA's alone (src/authz).
 *
 * A group is `{ "<app>": [roles] }`: each role is read in that app's roles only. A group binding a
 * jinbe role is a platform grant (power over the console and the API).
 */
export class GroupCatalogueUnavailableError extends Error {}

/** The permission that lets somebody hand out a group across the platform. */
export const ASSIGN_MEMBERSHIP = 'groups.members:write'

async function groups(): Promise<Record<string, Record<string, string[]>>> {
  try {
    return await redisRbacRepository.getGroups()
  } catch (err) {
    // Raises rather than answering "no groups": "nothing is declared" and "I could not tell" are
    // opposite facts, and the second one must never quietly authorize or quietly refuse.
    throw new GroupCatalogueUnavailableError(`The group catalogue could not be read: ${(err as Error).message}`)
  }
}

/** Every group OPA knows. Anything else confers nothing, wherever it is written. */
export async function declaredGroups(): Promise<string[]> {
  return Object.keys(await groups()).sort()
}

/** What the write path needs to know about a set of groups, in ONE read. */
export type GroupFacts = {
  /** OPA knows it. Anything else confers nothing, wherever it is written. */
  declared: boolean
  /** Confers a jinbe role — power over the platform itself. */
  platform: boolean
  /** Confers no role anywhere. */
  empty: boolean
}

/**
 * Answer for every group at once. A group conferring a jinbe role goes through the holding rule, the
 * target's second factor and the actor's step-up, whatever it carries.
 */
export async function groupFacts(names: readonly string[]): Promise<Map<string, GroupFacts>> {
  const all = await groups()
  const facts = new Map<string, GroupFacts>()
  for (const name of names) {
    const definition = all[name]
    if (!definition) {
      facts.set(name, { declared: false, platform: false, empty: true })
      continue
    }
    const grants = Object.values(definition).filter((roles) => (roles ?? []).length > 0)
    facts.set(name, {
      declared: true,
      platform: (definition[JINBE] ?? []).length > 0,
      empty: grants.length === 0,
    })
  }
  return facts
}
