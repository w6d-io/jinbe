import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// loadPlatform reads the gateway config: the headers its global header mutator fills from a template
// are kept apart (templatedHeaders), so a header-mutator gate leaves them to the template.

vi.mock('../../gateway/service.js', () => ({
  currentSpec: vi.fn(async () => ({
    authenticators: {},
    authorizers: { remote_json: { enabled: true, config: { remote: 'http://p/v1/data/rbac/allow', forward_response_headers_to_upstream: ['X-User-Groups'] } } },
    mutators: { header: { enabled: true, config: { headers: { 'x-user-id': '{{ print .Subject }}', 'x-user-groups': '{{ .Extra.groups }}', 'x-static': 'v' } } } },
    errors: {},
    errorFallback: ['json'],
  })),
}))

import { loadPlatform } from '../../sites/platform.js'
import { setKubeSites } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'

describe('loadPlatform identity', () => {
  beforeEach(() => {
    process.env.SITES_KUBE = 'kubeconfig'
    resetSitesConfig()
    setKubeSites({ ping: async () => {}, get: async () => null, apply: async () => {}, delete: async () => {}, listZones: async () => [] } as never)
  })

  afterEach(() => {
    process.env.SITES_KUBE = 'off'
    resetSitesConfig()
  })

  it('keeps the templated global headers apart, as spelled; static ones are not templated', async () => {
    const p = await loadPlatform()
    expect(p.templatedHeaders).toEqual(['x-user-id', 'x-user-groups'])
    expect(p.identityHeaders).toEqual(expect.arrayContaining(['x-user-id', 'x-user-groups', 'X-User-Groups']))
    expect(p.authorizerHeaders).toEqual({ remote_json: ['X-User-Groups'] })
  })
})
