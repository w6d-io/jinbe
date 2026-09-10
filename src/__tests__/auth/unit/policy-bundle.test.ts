import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createHash } from 'node:crypto'
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
        routes: {
          GET: {
            context: { segments: ['api', 'v1', 'context'], class: 'authorized', permission: 'context:read' },
          },
        },
      }),
    },
  },
]

const RULES = [
  {
    metadata: { name: 'authz-policy', namespace: 'ory' },
    data: { 'strada.rego': 'package strada.authz\n\ndefault allow := false\n' },
  },
]

describe('the policy bundle', () => {
  beforeEach(() => {
    service.forgetPolicyBundle()
    core.listNamespacedConfigMap.mockReset()
    // Deux sélecteurs, deux réponses : les faits et les règles ne vivent pas dans les mêmes
    // ConfigMaps, et un mock qui répondrait la même chose aux deux ne prouverait rien.
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego' ? { items: RULES } : { items: MODEL },
    )
    storeState.allGroupMemberships.mockReset()
    storeState.allGroupMemberships.mockResolvedValue(new Map([['subject-a', ['platform-operator']]]))
  })

  it('owns the root, and therefore carries everything', async () => {
    const { body } = await service.policyBundle()
    const files = await entriesOf(body)

    // Both the facts and the package of the rule: a root governs rule packages too, and a manifest
    // declaring only the data root has the whole bundle refused at every poll.
    expect(JSON.parse(files['.manifest']).roots).toEqual(['ory', 'strada/authz'])
    const data = JSON.parse(files['data.json'])
    // Shaped exactly as the loader it replaces shaped it, key suffix included — the policy addresses
    // it that way, and reshaping it here would silently rewrite every rule.
    expect(data.ory.authz['roles.json']).toEqual({ operator: ['context:read'] })
    expect(data.ory['strada-demo-api']['permissions.json'].routes.GET.context.class).toBe('authorized')
    expect(data.ory.membership).toEqual({ 'subject-a': ['platform-operator'] })
  })

  it('selects on the label the engine loader itself uses', async () => {
    await service.policyBundle()
    const selectors = core.listNamespacedConfigMap.mock.calls.map((c: [{ labelSelector: string }]) => c[0].labelSelector)
    expect(selectors).toContain('openpolicyagent.org/data=opa')
    expect(selectors).toContain('openpolicyagent.org/policy=rego')
  })

  it('carries the rules alongside the facts', async () => {
    const { body } = await service.policyBundle()
    const files = await entriesOf(body)

    expect(files['authz-policy.strada.rego']).toContain('package strada.authz')
  })

  it('moves the revision when a rule changes, not only when a fact does', async () => {
    // A revision that ignored the rules would have the engine answer 304 and keep deciding with the
    // previous ones while the repository says otherwise.
    const before = await service.policyBundle()

    service.forgetPolicyBundle()
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego'
        ? { items: [{ metadata: { name: 'authz-policy' }, data: { 'strada.rego': 'package strada.authz\n\ndefault allow := true\n' } }] }
        : { items: MODEL },
    )
    const after = await service.policyBundle()

    expect(after.revision).not.toBe(before.revision)
  })

  it('does not serve a cached bundle after a rule changed', async () => {
    // The regression this exists for: the revision was compared to the cache BEFORE the rules were
    // read, so a bundle cached once could never gain a rule — the engine kept deciding with rules
    // that were no longer anywhere in the repository, and the deployment reported success. Note the
    // absence of forgetPolicyBundle() below: every other test clears the cache first, which is
    // exactly why none of them saw it.
    const before = await service.policyBundle()
    expect(before.revision).toBeTruthy()

    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego'
        ? { items: [{ metadata: { name: 'authz-policy' }, data: { 'strada.rego': 'package strada.authz\n\nallow := true\n' } }] }
        : { items: MODEL },
    )
    const after = await service.policyBundle()

    expect(after.revision).not.toBe(before.revision)
    expect((await entriesOf(after.body))['authz-policy.strada.rego']).toContain('allow := true')
  })

  it('names a rule after where it came from, so a collision is visible', async () => {
    service.forgetPolicyBundle()
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego'
        ? {
            items: [
              { metadata: { name: 'a' }, data: { 'x.rego': 'package a' } },
              { metadata: { name: 'b' }, data: { 'x.rego': 'package b' } },
            ],
          }
        : { items: MODEL },
    )
    const files = await entriesOf((await service.policyBundle()).body)

    expect(Object.keys(files)).toContain('a.x.rego')
    expect(Object.keys(files)).toContain('b.x.rego')
  })

  it('claims a root for every package it carries', async () => {
    service.forgetPolicyBundle()
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego'
        ? {
            items: [
              { metadata: { name: 'a' }, data: { 'x.rego': 'package strada.authz\n' } },
              { metadata: { name: 'b' }, data: { 'y.rego': 'package strada.shared.time\n' } },
            ],
          }
        : { items: MODEL },
    )
    const files = await entriesOf((await service.policyBundle()).body)

    expect(JSON.parse(files['.manifest']).roots).toEqual(['ory', 'strada/authz', 'strada/shared/time'])
  })

  it('drops a root already covered by another, which the engine would refuse', async () => {
    service.forgetPolicyBundle()
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego'
        ? { items: [{ metadata: { name: 'a' }, data: { 'x.rego': 'package ory.helpers\n' } }] }
        : { items: MODEL },
    )
    const files = await entriesOf((await service.policyBundle()).body)

    expect(JSON.parse(files['.manifest']).roots).toEqual(['ory'])
  })

  it('refuses a rule that declares no package rather than have the bundle refused whole', async () => {
    service.forgetPolicyBundle()
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego'
        ? { items: [{ metadata: { name: 'a' }, data: { 'x.rego': 'default allow := false\n' } }] }
        : { items: MODEL },
    )
    await expect(service.policyBundle()).rejects.toThrow(/declares no package/)
  })

  it('refuses an empty rule rather than publish it', async () => {
    service.forgetPolicyBundle()
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego'
        ? { items: [{ metadata: { name: 'authz-policy' }, data: { 'strada.rego': '   ' } }] }
        : { items: MODEL },
    )
    await expect(service.policyBundle()).rejects.toThrow(/refusing to publish/)
  })

  it('accepts a deployment that keeps its rules on disk', async () => {
    // Absent is allowed for the rules, unlike the model: both arrangements have to coexist while
    // this is being adopted.
    service.forgetPolicyBundle()
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego' ? { items: [] } : { items: MODEL },
    )
    const files = await entriesOf((await service.policyBundle()).body)

    expect(Object.keys(files).filter((f) => f.endsWith('.rego'))).toHaveLength(0)
    expect(files['data.json']).toBeDefined()
  })

  it('refuses to publish an empty model rather than delete every route table', async () => {
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego' ? { items: RULES } : { items: [] },
    )
    await expect(service.policyBundle()).rejects.toThrow(service.PolicyBundleUnavailableError)
  })

  it('refuses the whole bundle when one document is malformed', async () => {
    // Publishing without it would remove what it granted, and the refusal that follows names a route
    // rather than a broken file.
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego'
        ? { items: RULES }
        : { items: [{ metadata: { name: 'authz' }, data: { 'roles.json': '{ not json' } }] },
    )
    await expect(service.policyBundle()).rejects.toThrow(/is not a document/)
  })

  describe('a table the policy could not decide against', () => {
    function withRoutes(routes: Record<string, unknown>) {
      return [
        MODEL[0],
        { metadata: { name: 'strada-demo-api' }, data: { 'permissions.json': JSON.stringify({ routes: { GET: routes } }) } },
      ]
    }

    function serving(routes: Record<string, unknown>) {
      core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
        labelSelector === 'openpolicyagent.org/policy=rego' ? { items: RULES } : { items: withRoutes(routes) },
      )
    }

    beforeEach(() => service.forgetPolicyBundle())

    it('refuses two routes of equal specificity, which make the winner produce two outputs', async () => {
      // Measured against the engine: this state does not pick one and does not refuse — evaluation
      // fails, and the adapter turns that into a 500 on the route. Refused here instead, it is a
      // bundle that does not publish and a rollout that does not complete.
      serving({
        left: { segments: ['api', '{v}', 'context'], class: 'public' },
        right: { segments: ['api', 'v1', '{what}'], class: 'public' },
      })
      await expect(service.policyBundle()).rejects.toThrow(/equal specificity/)
    })

    it('accepts two routes that overlap with DIFFERENT specificity, because one wins', async () => {
      serving({
        vehicle: { segments: ['api', 'v1', 'vehicles', '{id}'], class: 'authenticated' },
        summary: { segments: ['api', 'v1', 'vehicles', 'summary'], class: 'authenticated' },
      })
      await expect(service.policyBundle()).resolves.toBeDefined()
    })

    it('accepts two routes of equal specificity that cannot match the same path', async () => {
      serving({
        one: { segments: ['api', 'v1', 'context'], class: 'authenticated' },
        two: { segments: ['api', 'v1', 'audit'], class: 'authenticated' },
      })
      await expect(service.policyBundle()).resolves.toBeDefined()
    })

    it('refuses a class no rule implements', async () => {
      serving({ weird: { segments: ['api', 'v1', 'context'], class: 'internal' } })
      await expect(service.policyBundle()).rejects.toThrow(/no rule implements/)
    })

    it('refuses an authorized route that names no permission', async () => {
      // The hole the previous model had: a route without a permission authorized everybody.
      serving({ naked: { segments: ['api', 'v1', 'context'], class: 'authorized' } })
      await expect(service.policyBundle()).rejects.toThrow(/names no permission/)
    })

    it('refuses a route with no segments rather than match it against everything', async () => {
      serving({ empty: { class: 'authenticated' } })
      await expect(service.policyBundle()).rejects.toThrow(/declares no segments/)
    })
  })

  it('refuses when the cluster cannot be read', async () => {
    core.listNamespacedConfigMap.mockImplementation(async () => {
      throw new Error('configmaps is forbidden')
    })
    await expect(service.policyBundle()).rejects.toThrow(service.PolicyBundleUnavailableError)
  })

  it('refuses a ConfigMap that would collide with the memberships', async () => {
    // Named `membership`, it would overwrite the people with the model or the reverse depending on
    // iteration order. Refused rather than resolved by luck.
    core.listNamespacedConfigMap.mockImplementation(async ({ labelSelector }: { labelSelector: string }) =>
      labelSelector === 'openpolicyagent.org/policy=rego'
        ? { items: RULES }
        : { items: [...MODEL, { metadata: { name: 'membership' }, data: {} }] },
    )
    await expect(service.policyBundle()).rejects.toThrow(/collides/)
  })

  it('moves the revision when the roots change, not only when the bytes do', async () => {
    // The manifest is part of the artefact. A revision covering only data and rules let a corrected
    // roots derivation ship under the identity of the broken one, and the engine answered 304 and
    // went on refusing the bundle it already held.
    const files = await entriesOf((await service.policyBundle()).body)
    const manifest = JSON.parse(files['.manifest'])

    const forged = createHash('sha256')
      .update(files['data.json'])
      .update(`authz-policy.strada.rego\n${files['authz-policy.strada.rego']}`)
      .update(manifest.roots.join(','))
      .digest('hex')
      .slice(0, 16)

    expect(manifest.revision).toBe(forged)
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
