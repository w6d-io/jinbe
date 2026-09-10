import { describe, it, expect, vi, beforeEach } from 'vitest'

// The screen this feeds replaces editors that wrote where nothing reads. Three properties matter,
// and none of them is about formatting:
//   - only what the engines actually LOAD is shown (selected by the loader's own label),
//   - what the API server adds is pruned, or the two lines that matter are unreadable,
//   - a read failure raises: "nothing is enforced" and "I cannot tell" are opposite facts.

const { core, custom, loadFromCluster } = vi.hoisted(() => ({
  core: { listNamespacedConfigMap: vi.fn() },
  custom: { listNamespacedCustomObject: vi.fn() },
  loadFromCluster: vi.fn(),
}))

vi.mock('@kubernetes/client-node', () => {
  class CoreV1Api {}
  class CustomObjectsApi {}
  return {
    CoreV1Api,
    CustomObjectsApi,
    KubeConfig: class {
      loadFromCluster = loadFromCluster
      makeApiClient(kind: unknown) {
        return kind === CoreV1Api ? core : custom
      }
    },
  }
})

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getIdentity: vi.fn(async (id: string) =>
      id === 'known' ? { traits: { email: 'somebody@strada.eu' } } : Promise.reject(new Error('not found')),
    ),
  },
}))
vi.mock('../../../services/organisation-store.js', () => ({
  organisationStoreConfigured: vi.fn(() => true),
  organisationsById: vi.fn(async () => [{ id: 'org-a', name: 'Business', tenant: 'business', attributes: {} }]),
  // Who is in a group. Joined with what a group gives, because the model owns those two halves
  // separately: the groups change at a release, the memberships change daily.
  allGroupMemberships: vi.fn(async () => new Map<string, string[]>()),
}))

const store = await import('../../../services/organisation-store.js')
const service = await import('../../../services/enforced-config.service.js')

const RULE = {
  apiVersion: 'oathkeeper.ory.sh/v1alpha1',
  kind: 'Rule',
  metadata: {
    name: 'demo-api',
    namespace: 'ory',
    resourceVersion: '918273',
    uid: 'e6f2…',
    generation: 4,
    creationTimestamp: '2026-09-01T10:00:00Z',
    managedFields: [{ manager: 'argocd-controller' }],
    annotations: {
      'kubectl.kubernetes.io/last-applied-configuration': '{"the":"whole object again"}',
      'argocd.argoproj.io/tracking-id': 'ory-rules:oathkeeper.ory.sh/Rule:ory/demo-api',
    },
  },
  spec: { upstream: { url: 'http://strada-demo-api.ory.svc.cluster.local:8080' } },
  status: { validation: { valid: true } },
}

const POLICY_DATA = {
  metadata: { name: 'strada-demo-api', namespace: 'ory' },
  data: { 'permissions.json': '{\n  "routes": {}\n}\n' },
}

describe('the enforced configuration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    custom.listNamespacedCustomObject.mockResolvedValue({ items: [RULE] })
    core.listNamespacedConfigMap.mockResolvedValue({ items: [POLICY_DATA] })
  })

  it('shows only what the policy engine loads, selected by the loader label', async () => {
    await service.enforcedConfiguration()

    const [call] = core.listNamespacedConfigMap.mock.calls
    expect(call[0].labelSelector).toBe('openpolicyagent.org/data=opa')
  })

  it('prunes what the API server owns, so the two lines that matter are readable', async () => {
    const [rule] = await service.enforcedConfiguration()

    expect(rule.kind).toBe('Rule')
    for (const noise of ['resourceVersion', 'uid', 'generation', 'creationTimestamp', 'managedFields', 'status:']) {
      expect(rule.yaml, `${noise} should not be shown`).not.toContain(noise)
    }
    // The copy of the whole object that lives inside the object.
    expect(rule.yaml).not.toContain('last-applied-configuration')
    // But what says where it came from stays: that is the point of the screen.
    expect(rule.yaml).toContain('argocd.argoproj.io/tracking-id')
    expect(rule.yaml).toContain('strada-demo-api.ory.svc.cluster.local')
  })

  it('keeps an embedded document readable instead of one escaped line', async () => {
    const documents = await service.enforcedConfiguration()
    const data = documents.find((d) => d.kind === 'ConfigMap')!

    // A literal block, as it reads in the repository — not "{\n  \"routes\"…".
    expect(data.yaml).toContain('permissions.json: |')
    expect(data.yaml).not.toContain('\\n')
  })

  it('names what each object decides, in the reader\'s terms', async () => {
    const documents = await service.enforcedConfiguration()

    expect(documents.find((d) => d.kind === 'Rule')!.decides).toContain('authenticated')
    expect(documents.find((d) => d.kind === 'ConfigMap')!.decides).toContain('which permission each route requires')
  })

  it('reads the route table out as rows, so a screen need not parse it again', async () => {
    // Parsed here because the shape is known here. A console that parsed the same document would be
    // a second reader of it, free to disagree with the engine about what it says.
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [
        {
          metadata: { name: 'strada-demo-api', namespace: 'ory' },
          data: {
            'permissions.json': JSON.stringify({
              routes: {
                GET: {
                  context: { segments: ['api', 'v1', 'context'], class: 'authorized', permission: 'context:read' },
                  health: { segments: ['health', 'live'], class: 'public' },
                },
              },
            }),
          },
        },
      ],
    })

    const [, data] = await service.enforcedConfiguration()

    expect(data.routes).toEqual([
      { method: 'GET', path: '/api/v1/context', class: 'authorized', permission: 'context:read' },
      { method: 'GET', path: '/health/live', class: 'public' },
    ])
  })

  it('reads what each role carries, so a permission can be traced to the roles holding it', async () => {
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [
        {
          metadata: { name: 'authz', namespace: 'ory' },
          data: { 'roles.json': JSON.stringify({ operator: ['context:read'], viewer: [] }) },
        },
      ],
    })

    const [, data] = await service.enforcedConfiguration()

    expect(data.roles).toEqual([
      { role: 'operator', permissions: ['context:read'] },
      { role: 'viewer', permissions: [] },
    ])
  })

  it('costs the rows and never the document when the table cannot be parsed', async () => {
    // The YAML is still shown, so whoever asks why the rows are missing is looking at the document
    // that caused it.
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [{ metadata: { name: 'broken', namespace: 'ory' }, data: { 'permissions.json': '{ not json' } }],
    })

    const [, data] = await service.enforcedConfiguration()

    expect(data.routes).toBeUndefined()
    expect(data.yaml).toContain('name: broken')
  })

  it('names the person and the organisation behind a grant, and keeps the identifier when it cannot', async () => {
    // The last links of the chain a reader follows, joined from the two halves the model keeps apart:
    // `groups.json` says what a group gives per organisation, the directory says who is in it. A
    // subject present in the directory and absent from Kratos is the case worth seeing, so it is
    // shown by its identifier rather than dropped.
    vi.mocked(store.allGroupMemberships).mockResolvedValue(
      new Map([
        ['known', ['operators']],
        ['gone-from-the-directory', ['other-operators']],
      ]),
    )
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [
        {
          metadata: { name: 'authz', namespace: 'ory' },
          data: {
            'roles.json': JSON.stringify({ operator: ['context:read'] }),
            'groups.json': JSON.stringify({
              operators: { 'org-a': ['operator'] },
              'other-operators': { 'org-b': ['operator'] },
            }),
          },
        },
      ],
    })

    const [, data] = await service.enforcedConfiguration()

    expect(data.grants).toEqual([
      {
        subject: 'gone-from-the-directory',
        held: [{ organisation: 'org-b', roles: ['operator'], viaGroups: ['other-operators'] }],
      },
      {
        subject: 'known',
        email: 'somebody@strada.eu',
        held: [
          { organisation: 'org-a', organisationName: 'Business', roles: ['operator'], viaGroups: ['operators'] },
        ],
      },
    ])
  })

  it('shows the group a role came through, and every organisation for a group that grants in all', async () => {
    // Without the group a reader sees that somebody holds a role and cannot tell why, nor what to
    // change to take it away. `*` is the model's own way of saying "every organisation", so it is
    // shown as it is written rather than expanded into a guess.
    vi.mocked(store.allGroupMemberships).mockResolvedValue(new Map([['known', ['platform-operator']]]))
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [
        {
          metadata: { name: 'authz', namespace: 'ory' },
          data: { 'groups.json': JSON.stringify({ 'platform-operator': { '*': ['operator'] } }) },
        },
      ],
    })

    const [, data] = await service.enforcedConfiguration()

    expect(data.grants).toEqual([
      {
        subject: 'known',
        email: 'somebody@strada.eu',
        held: [{ organisation: '*', roles: ['operator'], viaGroups: ['platform-operator'] }],
      },
    ])
  })

  it('unions two groups granting in the same organisation, and names both', async () => {
    vi.mocked(store.allGroupMemberships).mockResolvedValue(new Map([['known', ['readers', 'writers']]]))
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [
        {
          metadata: { name: 'authz', namespace: 'ory' },
          data: {
            'groups.json': JSON.stringify({
              readers: { 'org-a': ['reader'] },
              writers: { 'org-a': ['writer'] },
            }),
          },
        },
      ],
    })

    const [, data] = await service.enforcedConfiguration()

    expect(data.grants?.[0].held).toEqual([
      {
        organisation: 'org-a',
        organisationName: 'Business',
        roles: ['reader', 'writer'],
        viaGroups: ['readers', 'writers'],
      },
    ])
  })

  it('costs the last hop and never the answer when the directory cannot be read', async () => {
    // A document that cannot be read means nobody knows what is enforced; a directory that cannot
    // answer costs a reader one column. Those are not the same failure.
    vi.mocked(store.allGroupMemberships).mockRejectedValue(new Error('the store is down'))
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [
        {
          metadata: { name: 'authz', namespace: 'ory' },
          data: {
            'roles.json': JSON.stringify({ operator: ['context:read'] }),
            'groups.json': JSON.stringify({ operators: { 'org-a': ['operator'] } }),
          },
        },
      ],
    })

    const [, data] = await service.enforcedConfiguration()

    expect(data.roles).toEqual([{ role: 'operator', permissions: ['context:read'] }])
    expect(data.grants).toEqual([])
  })

  it('raises rather than answering a short list when the cluster cannot be read', async () => {
    // An empty screen would say "nothing is enforced". That is the one answer that is certainly wrong.
    custom.listNamespacedCustomObject.mockRejectedValue(new Error('rules is forbidden'))

    await expect(service.enforcedConfiguration()).rejects.toThrow(service.EnforcedConfigUnavailableError)
  })
})
