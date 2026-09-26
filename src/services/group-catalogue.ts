import { redisRbacRepository } from './redis-rbac.repository.js'

/**
 * The groups jinbe publishes to OPA (Redis → OPAL → `data.bindings.groups`), read for the screens and
 * the write path — never to decide who may do what, which is OPA's alone (src/authz).
 *
 * A group is `{ "global": [roles], "<service>": [roles] }`: roles bound under `global` apply in every
 * service and every org — a platform grant rather than a tenant one.
 */
export class GroupCatalogueUnavailableError extends Error {}

/** The permission that lets somebody hand out a group across the platform. */
export const ASSIGN_MEMBERSHIP = 'admin.membership:write'

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
  /** Confers a `global` role — power in every service and every org. */
  everyOrganisation: boolean
  /** Confers no role anywhere. */
  empty: boolean
}

/**
 * Answer for every group at once. A group conferring a `global` role goes through the escalation
 * gate, the target's second factor and the actor's step-up, whatever it carries.
 */
export async function groupFacts(names: readonly string[]): Promise<Map<string, GroupFacts>> {
  const all = await groups()
  const facts = new Map<string, GroupFacts>()
  for (const name of names) {
    const definition = all[name]
    if (!definition) {
      facts.set(name, { declared: false, everyOrganisation: false, empty: true })
      continue
    }
    const grants = Object.values(definition).filter((roles) => (roles ?? []).length > 0)
    facts.set(name, {
      declared: true,
      everyOrganisation: (definition.global ?? []).length > 0,
      empty: grants.length === 0,
    })
  }
  return facts
}
