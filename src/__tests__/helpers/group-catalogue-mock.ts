/**
 * The group catalogue (the groups jinbe publishes to OPA), as the write path reads it — so the tests
 * drive one catalogue rather than a set of independent predicates each of which could be mocked
 * into agreeing.
 */
export type GroupDefinitions = Record<string, Record<string, string[]>>

/** Groups the suite assigns. `global` is every service and org — a platform grant rather than a tenant one. */
const DEFAULT_GROUPS: GroupDefinitions = {
  users: {},
  admins: { 'org-1': ['admin'] },
  devs: { 'org-1': ['dev'] },
  viewers: { 'org-1': ['viewer'] },
  operators: { 'org-1': ['operator'] },
  'kuma-viewers': { 'org-1': ['viewer'] },
  org_admins: { 'org-1': ['org-admin'] },
  super_admins: { global: ['super-admin'] },
}

export const groupCatalogue = { groups: { ...DEFAULT_GROUPS } as GroupDefinitions }

export function resetGroupCatalogue(): void {
  groupCatalogue.groups = { ...DEFAULT_GROUPS }
}

export class GroupCatalogueUnavailableError extends Error {}

import { vi } from 'vitest'

export function groupCatalogueMock() {
  return {
    GroupCatalogueUnavailableError,
    ASSIGN_MEMBERSHIP: 'admin.membership:write',
    declaredGroups: vi.fn(async () => Object.keys(groupCatalogue.groups).sort()),
    groupFacts: vi.fn(async (names: readonly string[]) => {
      const facts = new Map<string, { declared: boolean; everyOrganisation: boolean; empty: boolean }>()
      for (const name of names) {
        const definition = groupCatalogue.groups[name]
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
    }),
  }
}
