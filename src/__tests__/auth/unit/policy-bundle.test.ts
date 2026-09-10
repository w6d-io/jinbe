import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createGunzip } from 'node:zlib'
import { extract } from 'tar-stream'

// The artefact the engine decides against, carried whole. The properties that matter are all about
// what happens when something is MISSING, because this bundle owns the root: anything absent from it
// is deleted from the engine, and a deleted route table refuses every route of that service with a
// reason indistinguishable from a missing right.

const { core, storeState } = vi.hoisted(() => ({
  core: { listNamespacedConfigMap: vi.fn() },
  storeState: { allGroupMemberships: vi.fn() },
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
vi.mock('../../../services/organisation-store.js', () => storeState)

const service = await import('../../../services/policy-bundle.service.js')

async function entriesOf(body: Buffer): Promise<Record<string, string>> {
  const found: Record<string, string> = {}
  const tar = extract()
  const done = new Promise<void>((resolve, reject) => {
    tar.on('entry', (header, stream, next) => {
      const chunks: Buffer[] = []
      stream.on('data', (c: Buffer) => chunks.push(c))
      stream.on('end', () => {
        found[header.name] = Buffer.concat(chunks).toString('utf-8')
        next()
      })
      stream.resume()
    })
    tar.on('finish', () => resolve())
    tar.on('error', reject)
  })
  const gunzip = createGunzip()
  gunzip.pipe(tar)
  gunzip.end(body)
  await done
  return found
}

const MODEL = [
  {
    metadata: { name: 'authz', namespace: 'ory' },
    data: {
      'roles.json': JSON.stringify({ operator: ['context:read'] }),
      'groups.json': JSON.stringify({ 'platform-operator': { '*': ['operator'] } }),
    },
  },
  {
    metadata: { name: 'strada-demo-api', namespace: 'ory' },
    data: {
      'permissions.json': JSON.stringify({
        routes: { GET: { context: { segments: ['api', 'v1', 'context'], class: 'authorized' } } },
      }),
    },
  },
]

describe('the policy bundle', () => {
  beforeEach(() => {
    service.forgetPolicyBundle()
    core.listNamespacedConfigMap.mockReset()
    core.listNamespacedConfigMap.mockResolvedValue({ items: MODEL })
    storeState.allGroupMemberships.mockReset()
    storeState.allGroupMemberships.mockResolvedValue(new Map([['subject-a', ['platform-operator']]]))
  })

  it('owns the root, and therefore carries everything', async () => {
    const { body } = await service.policyBundle()
    const files = await entriesOf(body)

    expect(JSON.parse(files['.manifest']).roots).toEqual(['ory'])
    const data = JSON.parse(files['data.json'])
    // Shaped exactly as the loader it replaces shaped it, key suffix included — the policy addresses
    // it that way, and reshaping it here would silently rewrite every rule.
    expect(data.ory.authz['roles.json']).toEqual({ operator: ['context:read'] })
    expect(data.ory['strada-demo-api']['permissions.json'].routes.GET.context.class).toBe('authorized')
    expect(data.ory.membership).toEqual({ 'subject-a': ['platform-operator'] })
  })

  it('selects on the label the engine loader itself uses', async () => {
    await service.policyBundle()
    expect(core.listNamespacedConfigMap.mock.calls[0][0].labelSelector).toBe('openpolicyagent.org/data=opa')
  })

  it('refuses to publish an empty model rather than delete every route table', async () => {
    core.listNamespacedConfigMap.mockResolvedValue({ items: [] })
    await expect(service.policyBundle()).rejects.toThrow(service.PolicyBundleUnavailableError)
  })

  it('refuses the whole bundle when one document is malformed', async () => {
    // Publishing without it would remove what it granted, and the refusal that follows names a route
    // rather than a broken file.
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [{ metadata: { name: 'authz' }, data: { 'roles.json': '{ not json' } }],
    })
    await expect(service.policyBundle()).rejects.toThrow(/is not a document/)
  })

  it('refuses when the cluster cannot be read', async () => {
    core.listNamespacedConfigMap.mockRejectedValue(new Error('configmaps is forbidden'))
    await expect(service.policyBundle()).rejects.toThrow(service.PolicyBundleUnavailableError)
  })

  it('refuses a ConfigMap that would collide with the memberships', async () => {
    // Named `membership`, it would overwrite the people with the model or the reverse depending on
    // iteration order. Refused rather than resolved by luck.
    core.listNamespacedConfigMap.mockResolvedValue({
      items: [...MODEL, { metadata: { name: 'membership' }, data: {} }],
    })
    await expect(service.policyBundle()).rejects.toThrow(/collides/)
  })

  it('gives the same revision to the same content, and a new one when a group changes', async () => {
    const before = await service.policyBundle()
    service.forgetPolicyBundle()
    const again = await service.policyBundle()
    expect(again.revision).toBe(before.revision)

    service.forgetPolicyBundle()
    storeState.allGroupMemberships.mockResolvedValue(new Map([['subject-a', []]]))
    const after = await service.policyBundle()
    expect(after.revision).not.toBe(before.revision)
  })
})
