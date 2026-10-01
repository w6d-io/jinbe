/**
 * The group catalogue (the groups jinbe publishes to OPA), as the write path reads it — so the tests
 * drive one catalogue rather than a set of independent predicates each of which could be mocked
 * into agreeing.
 */
export type GroupDefinitions = Record<string, Record<string, string[]>>

/** Groups the suite assigns. A group binding a `jinbe` role is a platform grant (power over jinbe). */
const DEFAULT_GROUPS: GroupDefinitions = {
  users: {},
  admins: { payroll: ['admin'] },
  devs: { payroll: ['dev'] },
  viewers: { payroll: ['viewer'] },
  operators: { payroll: ['operator'] },
  super_admins: { jinbe: ['super_admin'] },
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
    ASSIGN_MEMBERSHIP: 'groups.members:write',
    declaredGroups: vi.fn(async () => Object.keys(groupCatalogue.groups).sort()),
    groupFacts: vi.fn(async (names: readonly string[]) => {
      const facts = new Map<string, { declared: boolean; platform: boolean; empty: boolean }>()
      for (const name of names) {
        const definition = groupCatalogue.groups[name]
        if (!definition) {
          facts.set(name, { declared: false, platform: false, empty: true })
          continue
        }
        const grants = Object.values(definition).filter((roles) => (roles ?? []).length > 0)
        facts.set(name, {
          declared: true,
          platform: (definition.jinbe ?? []).length > 0,
          empty: grants.length === 0,
        })
      }
      return facts
    }),
  }
}

/**
 * The per-group "Members must use 2FA" switch (second-factor/settings.ts) over the same catalogue. A
 * test sets `secondFactorSwitch.flags[name]`; an unset group stands for the stored default of the
 * suite's world — on for a group with a platform-wide role (the groups these suites grant).
 */
export const secondFactorSwitch = { flags: {} as Record<string, boolean>, fail: false }

export function resetSecondFactorSwitch(): void {
  secondFactorSwitch.flags = {}
  secondFactorSwitch.fail = false
}

export function secondFactorSettingsMock() {
  return {
    getGroupSecondFactorFlags: vi.fn(async () => {
      if (secondFactorSwitch.fail) throw new Error('ECONNREFUSED')
      const out = new Map<string, { required: boolean; explicit: boolean; default: boolean }>()
      for (const [name, def] of Object.entries(groupCatalogue.groups)) {
        const dflt = (def.jinbe ?? []).length > 0
        out.set(name, { required: secondFactorSwitch.flags[name] ?? dflt, explicit: name in secondFactorSwitch.flags, default: dflt })
      }
      return out
    }),
  }
}
