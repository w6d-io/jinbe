import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { opaService } from '../../../services/opa.service.js'

// canGrant is the mutation-time delegation gate. Unlike getUserInfo/simulate
// (which return null on infra error so the caller can distinguish "unknown"
// from "deny"), canGrant is FAIL-CLOSED: any error / non-2xx / missing /
// non-strictly-true result MUST resolve to `false` so an unreachable or
// misbehaving OPA can never authorise a privilege-changing grant.

const INPUT = {
  actor: { email: 'actor@example.com' },
  target_group: 'jinbe-viewers',
  target_org: 'org_a',
}

function okJson(body: unknown) {
  return { ok: true, json: vi.fn().mockResolvedValue(body) } as unknown as Response
}

describe('opaService.canGrant — fail-closed delegation gate', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns true only when OPA replies 2xx with result === true', async () => {
    const fetchMock = vi.fn().mockResolvedValue(okJson({ result: true }))
    global.fetch = fetchMock as unknown as typeof fetch

    await expect(opaService.canGrant(INPUT)).resolves.toBe(true)

    // Sends ONLY the email in input (actor perms resolved server-side by rego),
    // to the delegation.can_grant document.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toContain('/v1/data/rbac/delegation/can_grant')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body)).toEqual({ input: INPUT })
  })

  it('returns false when result === false', async () => {
    global.fetch = vi.fn().mockResolvedValue(okJson({ result: false })) as unknown as typeof fetch
    await expect(opaService.canGrant(INPUT)).resolves.toBe(false)
  })

  it('returns false when result is missing (undefined document)', async () => {
    global.fetch = vi.fn().mockResolvedValue(okJson({})) as unknown as typeof fetch
    await expect(opaService.canGrant(INPUT)).resolves.toBe(false)
  })

  it('returns false for a truthy-but-non-boolean result (strict === true)', async () => {
    global.fetch = vi.fn().mockResolvedValue(okJson({ result: 'true' })) as unknown as typeof fetch
    await expect(opaService.canGrant(INPUT)).resolves.toBe(false)
  })

  it('returns false on a non-2xx response (e.g. OPA 500)', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: vi.fn().mockResolvedValue({ result: true }),
    } as unknown as Response) as unknown as typeof fetch

    await expect(opaService.canGrant(INPUT)).resolves.toBe(false)
  })

  it('returns false when fetch rejects (OPA unreachable / aborted)', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED')) as unknown as typeof fetch
    await expect(opaService.canGrant(INPUT)).resolves.toBe(false)
  })
})
