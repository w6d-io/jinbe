import { beforeEach, describe, expect, it, vi } from 'vitest'

// loadPlatform hands render the impersonation settings only when the feature is on: off, the
// platform carries no trace of it, and the rendered sites are what they were.

const h = vi.hoisted(() => ({ env: {} as Record<string, unknown> }))

vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in h.env ? h.env[k as string] : t[k as keyof typeof t]) }) }
})

import { loadPlatform } from '../../sites/platform.js'
import { render } from '../../sites/render.js'
import { resetSitesConfig } from '../../sites/config.js'
import { payrollSite } from '../sites/fixtures.js'

const CHECK = 'http://auth-jinbe:8080/api/oathkeeper/impersonation/session'

beforeEach(() => {
  process.env.SITES_KUBE = 'off'
  resetSitesConfig()
  h.env = {}
})

describe('loadPlatform and impersonation', () => {
  it('carries nothing with the flag off, even when a check URL is set', async () => {
    h.env = { IMPERSONATION_ENABLED: false, IMPERSONATION_CHECK_URL: CHECK }
    const p = await loadPlatform()
    expect('impersonation' in p).toBe(false)
    expect(JSON.stringify(render(payrollSite(), p))).not.toContain('impersonat')
  })

  it('carries the cookie name and the check URL with the flag on, and render uses them', async () => {
    h.env = { IMPERSONATION_ENABLED: true, IMPERSONATION_CHECK_URL: CHECK, IMPERSONATION_COOKIE_NAME: 'support_view' }
    const p = await loadPlatform()
    expect(p.impersonation).toEqual({ cookie: 'support_view', checkUrl: CHECK })
    const web = render(payrollSite(), p).siteCr.spec.gates.find((g) => g.name === 'web')!
    expect(web.authenticators[0]).toMatchObject({ handler: 'cookie_session', config: { check_session_url: CHECK, only: ['support_view'] } })
    expect(web.authenticators[1]).toEqual({ handler: 'cookie_session' })
  })
})
