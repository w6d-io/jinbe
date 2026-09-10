/**
 * The authorization model, as the write path now reads it.
 *
 * The gates deciding whether handing out a group needs the actor's authority, the target's second
 * factor and the actor's step-up used to ask the retired model, which answered "not needed" for
 * every group it had never held. They ask this now, so the tests drive a model rather than a set of
 * independent predicates each of which could be mocked into agreeing.
 */
export type GroupDefinitions = Record<string, Record<string, string[]>>

/** Groups the suite assigns. `*` is every organisation — a platform grant rather than a tenant one. */
const DEFAULT_GROUPS: GroupDefinitions = {
  users: {},
  admins: { 'org-1': ['admin'] },
  devs: { 'org-1': ['dev'] },
  viewers: { 'org-1': ['viewer'] },
  operators: { 'org-1': ['operator'] },
  'kuma-viewers': { 'org-1': ['viewer'] },
  org_admins: { 'org-1': ['org-admin'] },
  super_admins: { '*': ['super-admin'] },
}

export const authorizationModel = { groups: { ...DEFAULT_GROUPS } as GroupDefinitions }

export function resetAuthorizationModel(): void {
  authorizationModel.groups = { ...DEFAULT_GROUPS }
}

export class AuthorizationModelUnavailableError extends Error {}

import { vi } from 'vitest'

export function authorizationModelMock() {
  return {
    AuthorizationModelUnavailableError,
    ASSIGN_MEMBERSHIP: 'admin.membership:write',
    declaredGroups: vi.fn(async () => Object.keys(authorizationModel.groups).sort()),
    groupFacts: vi.fn(async (names: readonly string[]) => {
      const facts = new Map<string, { declared: boolean; everyOrganisation: boolean; empty: boolean }>()
      for (const name of names) {
        const definition = authorizationModel.groups[name]
        if (!definition) {
          facts.set(name, { declared: false, everyOrganisation: false, empty: true })
          continue
        }
        const grants = Object.values(definition).filter((roles) => (roles ?? []).length > 0)
        facts.set(name, {
          declared: true,
          everyOrganisation: (definition['*'] ?? []).length > 0,
          empty: grants.length === 0,
        })
      }
      return facts
    }),
  }
}
