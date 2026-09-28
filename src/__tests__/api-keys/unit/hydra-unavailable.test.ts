import { afterEach, describe, expect, it, vi } from 'vitest'
import { HydraService, HydraUnavailableError } from '../../../services/hydra.service.js'

describe('Hydra unreachable', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('a network failure becomes HydraUnavailableError naming the cause, not a raw fetch error', async () => {
    const dns = Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } })
    vi.stubGlobal('fetch', vi.fn(async () => { throw dns }))
    const svc = new HydraService() as unknown as { request: (p: string) => Promise<unknown> }
    const err = await svc.request('/admin/clients').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(HydraUnavailableError)
    expect((err as Error).message).toContain('ENOTFOUND')
  })
})
