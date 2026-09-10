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
  'platform-operator': { '*': ['operator'] },
  'premium-operator': { 'org-premium': ['operator'] },
  'named-like-an-admin': {},
  'empty-everywhere': { '*': [] },
}

function serving(groups: unknown) {
  core.listNamespacedConfigMap.mockResolvedValue({
    items: [{ metadata: { name: 'authz' }, data: { 'groups.json': JSON.stringify(groups) } }],
  })
}

describe('who may hand out rights', () => {
  beforeEach(() => {
    core.listNamespacedConfigMap.mockReset()
    store.groupsForSubjects.mockReset()
    serving(GROUPS)
  })

  it('reads global power off the shape, not off the name', async () => {
    // A group called `named-like-an-admin` that grants nothing is not powerful, and one called
    // anything at all that grants under `*` is. Keying on names is how a same-named but powerless
    // group waves somebody through.
    expect([...(await model.globalPowerGroups())]).toEqual(['platform-operator'])
  })

  it('does not count a group that names every organisation but no role', async () => {
    expect((await model.globalPowerGroups()).has('empty-everywhere')).toBe(false)
  })

  it('does not count a group scoped to one organisation', async () => {
    expect((await model.globalPowerGroups()).has('premium-operator')).toBe(false)
  })

  it('says yes for a subject holding such a group', async () => {
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-a', ['platform-operator']]]))
    expect(await model.holdsGlobalPower('subject-a')).toBe(true)
    expect(store.groupsForSubjects).toHaveBeenCalledWith(['subject-a'])
  })

  it('says no for a subject holding only an organisation-scoped group', async () => {
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-b', ['premium-operator']]]))
    expect(await model.holdsGlobalPower('subject-b')).toBe(false)
  })

  it('says no for a subject in no group, without asking the model twice', async () => {
    store.groupsForSubjects.mockResolvedValue(new Map())
    expect(await model.holdsGlobalPower('stranger')).toBe(false)
  })

  it('refuses an empty identity before reading anything', async () => {
    expect(await model.holdsGlobalPower('')).toBe(false)
    expect(store.groupsForSubjects).not.toHaveBeenCalled()
    expect(core.listNamespacedConfigMap).not.toHaveBeenCalled()
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

  it('offers every declared group to somebody with global power, and nothing to anybody else', async () => {
    store.groupsForSubjects.mockResolvedValue(new Map([['subject-a', ['platform-operator']]]))
    expect(await model.assignableGroupsFor('subject-a')).toEqual([
      'empty-everywhere',
      'named-like-an-admin',
      'platform-operator',
      'premium-operator',
    ])

    store.groupsForSubjects.mockResolvedValue(new Map([['subject-b', ['premium-operator']]]))
    expect(await model.assignableGroupsFor('subject-b')).toEqual([])
  })

  it('raises when the model cannot be read, rather than answering "nobody is powerful"', async () => {
    // The two are opposite facts. Answering false here would refuse every assignment with a message
    // that reads like a missing right; the caller must be able to tell them apart.
    core.listNamespacedConfigMap.mockRejectedValue(new Error('configmaps is forbidden'))
    store.groupsForSubjects.mockResolvedValue(new Map())
    await expect(model.holdsGlobalPower('subject-a')).rejects.toThrow(
      model.AuthorizationModelUnavailableError,
    )
  })

  it('raises on a malformed document rather than reading past it', async () => {
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [{ metadata: { name: 'authz' }, data: { 'groups.json': '{ not json' } }],
    })
    await expect(model.globalPowerGroups()).rejects.toThrow(/is not a document/)
  })

  it('ignores a ConfigMap that carries no groups at all', async () => {
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [
        { metadata: { name: 'strada-demo-api' }, data: { 'permissions.json': '{}' } },
        { metadata: { name: 'authz' }, data: { 'groups.json': JSON.stringify(GROUPS) } },
      ],
    })
    expect([...(await model.globalPowerGroups())]).toEqual(['platform-operator'])
  })
})
