import type { GroupsFile, GroupDefinition } from '../../../schemas/rbac/groups.schema.js'

/**
 * Creates a sample groups file fixture
 */
export function createGroupsFixture(overrides: Partial<GroupsFile> = {}): GroupsFile {
  return {
    emails: {},
    groups: {
      admins: { jinbe: ['admin'], kuma: ['admin'] },
      infra: { jinbe: ['operator'], kuma: ['operator'] },
      devs: { jinbe: ['editor', 'viewer'], kuma: ['editor'] },
      viewers: { jinbe: ['viewer'], kuma: ['viewer'] },
    },
    ...overrides,
  }
}

/**
 * Creates an empty groups file
 */
export function createEmptyGroupsFixture(): GroupsFile {
  return {
    emails: {},
    groups: {},
  }
}

/**
 * Creates a groups file with super_admins tier
 */
export function createFullGroupsFixture(): GroupsFile {
  return {
    emails: {},
    groups: {
      super_admins: {
        global: ['super_admin'],
        jinbe: ['admin'],
        kuma: ['admin'],
      },
      admins: {
        jinbe: ['admin'],
        kuma: ['admin'],
      },
      infra: {
        jinbe: ['operator'],
        kuma: ['operator'],
      },
      devs: {
        jinbe: ['editor'],
        kuma: ['editor'],
      },
      viewers: {
        jinbe: ['viewer'],
        kuma: ['viewer'],
      },
    },
  }
}

/**
 * Creates a single group definition
 */
export function createGroupDefinition(
  services: Record<string, string[]> = {}
): GroupDefinition {
  return {
    jinbe: ['viewer'],
    ...services,
  }
}
