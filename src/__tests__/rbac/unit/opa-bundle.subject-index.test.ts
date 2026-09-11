import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createGunzip } from 'node:zlib'
import { extract } from 'tar-stream'
import { Readable } from 'node:stream'

// The bundle must carry a membership index keyed on the Kratos identity id, not only on the email.
// The email is a mutable trait a user can change from the settings flow; keying authorization on it
// means a rename moves someone's permissions, and a reused address inherits them. The id index is
// published alongside the email one so the policy can move without a flag day.

const { redisModule, kratosModule } = vi.hoisted(() => {
  const repo = {
    getRego: vi.fn().mockResolvedValue('package rbac\ndefault allow = false\n'),
    getAllForBundle: vi.fn().mockResolvedValue({ groups: {}, roles: {}, routeMaps: {} }),
    getBundleEtag: vi.fn().mockResolvedValue(null),
  }
  return {
    redisModule: { redisRbacRepository: repo },
    kratosModule: {
      kratosService: { getAllIdentitiesWithBindings: vi.fn() },
    },
  }
})

vi.mock('../../../services/redis-rbac.repository.js', () => redisModule)
vi.mock('../../../services/kratos.service.js', () => kratosModule)

import { opaBundleService } from '../../../services/opa-bundle.service.js'

function binding(id: string, groups: string[]) {
  return { groups, organizations: [], primaryOrganization: null, active: true, id, name: null }
}

async function readDataJson(buffer: Buffer): Promise<Record<string, never>> {
  const entries: Record<string, string> = {}
  const tar = extract()
  const done = new Promise<void>((resolve, reject) => {
    tar.on('entry', (header, stream, next) => {
      const chunks: Buffer[] = []
      stream.on('data', (c: Buffer) => chunks.push(c))
      stream.on('end', () => {
        entries[header.name] = Buffer.concat(chunks).toString()
        next()
      })
      stream.resume()
    })
    tar.on('finish', () => resolve())
    tar.on('error', reject)
  })
  Readable.from(buffer).pipe(createGunzip()).pipe(tar)
  await done
  return JSON.parse(entries['data.json'])
}

describe('OPA bundle — subject index', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // The service caches the built bundle; each case must build its own.
    ;(opaBundleService as unknown as { cachedBundle: Buffer | null; cachedEtag: string | null }).cachedBundle = null
    ;(opaBundleService as unknown as { cachedEtag: string | null }).cachedEtag = null
  })

  it('publishes membership keyed on the identity id as well as the email', async () => {
    kratosModule.kratosService.getAllIdentitiesWithBindings.mockResolvedValue(
      new Map([['ada@strada.eu', binding('9f1c0000-0000-0000-0000-000000000001', ['admins'])]]),
    )

    const result = await opaBundleService.getBundle()
    const data = (await readDataJson(result!.buffer)) as unknown as {
      bindings: { group_membership: Record<string, string[]>; group_membership_by_id: Record<string, string[]> }
    }

    expect(data.bindings.group_membership['ada@strada.eu']).toEqual(['admins'])
    expect(data.bindings.group_membership_by_id['9f1c0000-0000-0000-0000-000000000001']).toEqual(['admins'])
  })

  it('keeps the same subject when the email changes', async () => {
    const id = '9f1c0000-0000-0000-0000-000000000001'
    kratosModule.kratosService.getAllIdentitiesWithBindings.mockResolvedValue(
      new Map([['renamed@strada.eu', binding(id, ['admins'])]]),
    )

    const data = (await readDataJson((await opaBundleService.getBundle())!.buffer)) as unknown as {
      bindings: { group_membership: Record<string, string[]>; group_membership_by_id: Record<string, string[]> }
    }

    // The email index followed the rename; the id index did not move.
    expect(data.bindings.group_membership['ada@strada.eu']).toBeUndefined()
    expect(data.bindings.group_membership_by_id[id]).toEqual(['admins'])
  })

  it('publishes an empty index rather than a partial one when Kratos fails', async () => {
    kratosModule.kratosService.getAllIdentitiesWithBindings.mockRejectedValue(new Error('unreachable'))

    const data = (await readDataJson((await opaBundleService.getBundle())!.buffer)) as unknown as {
      bindings: { group_membership: Record<string, string[]>; group_membership_by_id: Record<string, string[]> }
    }

    expect(data.bindings.group_membership).toEqual({})
    expect(data.bindings.group_membership_by_id).toEqual({})
  })
})
