import { describe, it, expect, vi, beforeEach } from 'vitest'

// The gate that decides who may hand out rights. It reads the SAME ConfigMaps the artefact carries,
// so a decision this service makes about its own API cannot disagree with one the engine makes about
// somebody else's — and it is keyed on the immutable identity, never on an address.

const { core, store } = vi.hoisted(() => ({
  core: { listNamespacedConfigMap: vi.fn() },
  store: { groupsForSubjects: vi.fn() },
}))

vi.mock('@kubernetes/client-node', () => {
  class CoreV1Api {}
  return {
    CoreV1Api,
    KubeConfig: class {
      loadFromCluster() {}
      makeApiClient() {
        return core
      }
    },
  }
})
vi.mock('../../../services/organisation-store.js', () => store)
vi.mock('node:fs/promises', () => ({ readFile: vi.fn().mockResolvedValue('ory\n') }))

const model = await import('../../../services/authorization-model.service.js')

const GROUPS = {
  'platform-admin': { '*': ['platform-admin'] },
  'membership-admin': { '*': ['membership-admin'] },
  'platform-auditor': { '*': ['platform-auditor'] },
  'premium-operator': { 'org-premium': ['operator'] },
  // Grants membership writes INSIDE one organisation. Administering the platform is not an act
  // inside a company, so this must not let its holder hand out a group anywhere.
  'premium-membership': { 'org-premium': ['membership-admin'] },
  'named-like-an-admin': {},
  'empty-everywhere': { '*': [] },
}

const ROLES = {
  'platform-admin': ['admin:read', 'admin:write'],
  'membership-admin': ['admin:read', 'admin.membership:write'],
  'platform-auditor': ['admin:read'],
  operator: ['context:read'],
}

function serving(groups: unknown, roles: unknown = ROLES) {
  core.listNamespacedConfigMap.mockResolvedValue({
    items: [
      {
        metadata: { name: 'authz' },
        data: { 'groups.json': JSON.stringify(groups), 'roles.json': JSON.stringify(roles) },
      },
    ],
  })
}

describe('who may hand out rights', () => {
  beforeEach(() => {
    core.listNamespacedConfigMap.mockReset()
    store.groupsForSubjects.mockReset()
    serving(GROUPS)
  })

  it('reads what somebody may do across the platform from the roles their groups give under *', async () => {
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-a', ['platform-admin']]]))
    expect(await model.platformPermissions('subject-a')).toEqual(['admin:read', 'admin:write'])
  })

  it('admits an ancestor for a descendant, which is the model\'s one implication', async () => {
    // `platform-admin` holds `admin:write`; handing out a group needs `admin.membership:write`.
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-a', ['platform-admin']]]))
    expect(await model.holdsPlatformPermission('subject-a', model.ASSIGN_MEMBERSHIP)).toBe(true)
  })

  it('admits the exact permission', async () => {
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-m', ['membership-admin']]]))
    expect(await model.holdsPlatformPermission('subject-m', model.ASSIGN_MEMBERSHIP)).toBe(true)
  })

  it('refuses a sibling: reading everything is not writing memberships', async () => {
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-v', ['platform-auditor']]]))
    expect(await model.holdsPlatformPermission('subject-v', model.ASSIGN_MEMBERSHIP)).toBe(false)
  })

  it('IGNORES an organisation-scoped grant, because administering the platform is not an act in one', async () => {
    // The distinction the previous predicate could not make: holding membership writes inside one
    // company must not let somebody hand out a group everywhere.
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-p', ['premium-membership']]]))
    expect(await model.holdsPlatformPermission('subject-p', model.ASSIGN_MEMBERSHIP)).toBe(false)
  })

  it('is not fooled by a group that grants everywhere but carries nothing', async () => {
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-e', ['empty-everywhere', 'named-like-an-admin']]]))
    expect(await model.holdsPlatformPermission('subject-e', model.ASSIGN_MEMBERSHIP)).toBe(false)
  })

  it('resolves rights the way the policy resolves them: named organisation UNION every organisation', async () => {
    // `*` is a second source, not a fallback for the absence of the other. A holder of both must get
    // both, or the resolution here would disagree with the one that enforces.
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [
        {
          metadata: { name: 'authz' },
          data: {
            'groups.json': JSON.stringify({
              here: { 'org-1': ['local'] },
              everywhere: { '*': ['global'] },
            }),
            'roles.json': JSON.stringify({ local: ['thing:read'], global: ['other:write'] }),
          },
        },
      ],
    })
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-a', ['here', 'everywhere']]]))

    expect(await model.rightsOf('subject-a', 'org-1')).toEqual({
      groups: ['here', 'everywhere'],
      roles: ['global', 'local'],
      permissions: ['other:write', 'thing:read'],
    })
  })

  it('does not carry an organisation-scoped role into another organisation', async () => {
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [
        {
          metadata: { name: 'authz' },
          data: {
            'groups.json': JSON.stringify({ here: { 'org-1': ['local'] } }),
            'roles.json': JSON.stringify({ local: ['thing:read'] }),
          },
        },
      ],
    })
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-a', ['here']]]))

    expect(await model.rightsOf('subject-a', 'org-2')).toEqual({
      groups: ['here'],
      roles: [],
      permissions: [],
    })
  })

  it('offers every declared group to somebody who may hand one out, and nothing to anybody else', async () => {
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-m', ['membership-admin']]]))
    expect(await model.assignableGroupsFor('subject-m')).toEqual(Object.keys(GROUPS).sort())

    // An auditor reads everything and hands out nothing.
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-v', ['platform-auditor']]]))
    expect(await model.assignableGroupsFor('subject-v')).toEqual([])
  })

  it('raises when the model cannot be read, rather than answering "nobody is powerful"', async () => {
    // The two are opposite facts. Answering false here would refuse every assignment with a message
    // that reads like a missing right; the caller must be able to tell them apart.
    core.listNamespacedConfigMap.mockRejectedValue(new Error('configmaps is forbidden'))
    store.groupsForSubjects.mockResolvedValue(new Map())
    await expect(model.holdsPlatformPermission('subject-a', model.ASSIGN_MEMBERSHIP)).rejects.toThrow(
      model.AuthorizationModelUnavailableError,
    )
  })

  it('raises on a malformed document rather than reading past it', async () => {
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [{ metadata: { name: 'authz' }, data: { 'groups.json': '{ not json' } }],
    })
    await expect(model.platformPermissions('subject-a')).rejects.toThrow(/is not a document/)
  })

  it('ignores a ConfigMap that carries no groups at all', async () => {
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-a', ['platform-admin']]]))
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [
        { metadata: { name: 'strada-demo-api' }, data: { 'permissions.json': '{}' } },
        {
          metadata: { name: 'authz' },
          data: { 'groups.json': JSON.stringify(GROUPS), 'roles.json': JSON.stringify(ROLES) },
        },
      ],
    })
    expect(await model.platformPermissions('subject-a')).toEqual(['admin:read', 'admin:write'])
  })
})
