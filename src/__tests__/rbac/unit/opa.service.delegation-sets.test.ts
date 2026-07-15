import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { opaService } from '../../../services/opa.service.js'

// manageableOrgs / assignableGroups read set-valued delegation rules. OPA
// serialises a rego set as a JSON array. Both are FAIL-CLOSED to [] so an
// unreachable/erroring OPA scopes the actor to nothing (never grants reach).

function okJson(body: unknown) {
  return { ok: true, json: vi.fn().mockResolvedValue(body) } as unknown as Response
}

describe('opaService delegation set reads', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })
  afterEach(() => vi.restoreAllMocks())

  describe.each([
    ['manageableOrgs', 'manageable_orgs', (e: string) => opaService.manageableOrgs(e)],
    ['assignableGroups', 'assignable_groups', (e: string) => opaService.assignableGroups(e)],
  ] as const)('%s', (_name, rule, call) => {
    it(`returns the array and sends email-only input to ${rule}`, async () => {
      const fetchMock = vi.fn().mockResolvedValue(okJson({ result: ['a', 'b'] }))
      global.fetch = fetchMock as unknown as typeof fetch

      await expect(call('actor@example.com')).resolves.toEqual(['a', 'b'])

      const [url, init] = fetchMock.mock.calls[0]
      expect(String(url)).toContain(`/v1/data/rbac/delegation/${rule}`)
      expect(init.method).toBe('POST')
      expect(JSON.parse(init.body)).toEqual({ input: { actor: { email: 'actor@example.com' } } })
    })

    it('returns [] when result is missing', async () => {
      global.fetch = vi.fn().mockResolvedValue(okJson({})) as unknown as typeof fetch
      await expect(call('a@b.io')).resolves.toEqual([])
    })

    it('returns [] when result is not an array (e.g. undefined document → {})', async () => {
      global.fetch = vi.fn().mockResolvedValue(okJson({ result: { org: true } })) as unknown as typeof fetch
      await expect(call('a@b.io')).resolves.toEqual([])
    })

    it('returns [] on a non-2xx response', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: vi.fn().mockResolvedValue({ result: ['x'] }),
      } as unknown as Response) as unknown as typeof fetch
      await expect(call('a@b.io')).resolves.toEqual([])
    })

    it('returns [] when fetch rejects (OPA unreachable)', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED')) as unknown as typeof fetch
      await expect(call('a@b.io')).resolves.toEqual([])
    })
  })
})
