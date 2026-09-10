import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createGunzip } from 'node:zlib'
import { extract } from 'tar-stream'

// The artefact the authorization engine decides against. Three properties carry the whole design,
// and none of them is about packaging:
//   - it declares its ROOTS, so it owns one subtree and cannot delete the datasets it does not carry
//   - its revision is a hash of its content, so an unchanged directory costs a 304 and the revision
//     the engine reports means something
//   - a store that cannot be read RAISES; serving "nobody belongs to anything" would have the engine
//     activate it and remove everybody's access in one poll

const { storeState } = vi.hoisted(() => ({
  storeState: { allGroupMemberships: vi.fn(), organisationStoreConfigured: vi.fn(() => true) },
}))

vi.mock('../../../services/organisation-store.js', () => storeState)

const service = await import('../../../services/membership-bundle.service.js')

/** Read the tar.gz back, so the assertions are about what an engine would actually receive. */
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

describe('the membership bundle', () => {
  beforeEach(() => {
    service.forgetMembershipBundle()
    storeState.allGroupMemberships.mockReset()
    storeState.allGroupMemberships.mockResolvedValue(
      new Map([
        ['subject-b', ['support']],
        ['subject-a', ['ops', 'support']],
      ]),
    )
  })

  it('declares the one subtree it owns, so it cannot delete the datasets it does not carry', async () => {
    const { body } = await service.membershipBundle()
    const manifest = JSON.parse((await entriesOf(body))['.manifest'])

    expect(manifest.roots).toEqual(['ory/membership'])
  })

  it('carries the memberships under that subtree', async () => {
    const { body } = await service.membershipBundle()
    const data = JSON.parse((await entriesOf(body))['data.json'])

    expect(data.ory.membership).toEqual({
      'subject-a': ['ops', 'support'],
      'subject-b': ['support'],
    })
  })

  it('gives the same revision to the same directory, whatever the order it was read in', async () => {
    // A revision that changed on every build would make every poll a full download and turn the
    // engine's reported revision into noise.
    const first = await service.membershipBundle()

    service.forgetMembershipBundle()
    storeState.allGroupMemberships.mockResolvedValue(
      new Map([
        ['subject-a', ['ops', 'support']],
        ['subject-b', ['support']],
      ]),
    )
    const second = await service.membershipBundle()

    expect(second.revision).toBe(first.revision)
  })

  it('changes revision when somebody changes group', async () => {
    const before = await service.membershipBundle()

    service.forgetMembershipBundle()
    storeState.allGroupMemberships.mockResolvedValue(new Map([['subject-a', ['ops']]]))
    const after = await service.membershipBundle()

    expect(after.revision).not.toBe(before.revision)
  })

  it('raises when the store cannot be read, instead of serving an empty directory', async () => {
    // The one failure that must never be packaged: the engine treats what it receives as the whole
    // truth for this subtree.
    storeState.allGroupMemberships.mockRejectedValue(new Error('store unavailable'))

    await expect(service.membershipBundle()).rejects.toThrow('store unavailable')
  })
})
