/**
 * How a held group becomes a permission — and nothing else.
 *
 * NO IMPORTS, on purpose. There are two implementations of one model: this one, and the policy the
 * engine enforces. Same documents, two resolutions, and nothing would notice them drifting apart —
 * so this one is run side by side with `opa eval` over the same worlds and compared, by
 * `ory/scripts/compare-resolvers.py` in the infrastructure repository.
 *
 * That comparison has to import this and nothing more. When it lived beside the code that reads the
 * cluster and the database, importing it validated the whole environment and exited: a pure function
 * in an impure module is a function nobody can call.
 */

/** `{ "<group>": { "<organisation>": ["<role>"] } }`, as `groups.json` holds it. */
export type Groups = Record<string, Record<string, string[]>>

/** `{ "<role>": ["<permission>"] }`, as `roles.json` holds it. */
export type Roles = Record<string, string[]>

/** Every organisation at once. A group naming it grants wherever the holder happens to be. */
export const EVERY_ORGANISATION = '*'

/** What somebody holds, resolved the way the policy resolves it. */
export interface HeldRights {
  groups: string[]
  roles: string[]
  permissions: string[]
}

/**
 * Mirrors `carried_roles` and `permissions` in `strada.authz`: a group gives roles in a named
 * organisation OR in every one, both are read because `*` is a second source rather than a fallback
 * for the absence of the other, and then each role carries its permissions.
 */
export function resolveRights(
  documents: { groups: Groups; roles: Roles },
  heldGroups: readonly string[],
  organisationId: string,
): HeldRights {
  const roles = new Set<string>()
  for (const group of heldGroups) {
    const byOrganisation = documents.groups[group] ?? {}
    for (const role of byOrganisation[organisationId] ?? []) roles.add(role)
    for (const role of byOrganisation[EVERY_ORGANISATION] ?? []) roles.add(role)
  }

  const permissions = new Set<string>()
  for (const role of roles) {
    for (const permission of documents.roles[role] ?? []) permissions.add(permission)
  }

  return { groups: [...heldGroups], roles: [...roles].sort(), permissions: [...permissions].sort() }
}
