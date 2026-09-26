import { describe, it, expect, beforeEach, vi } from 'vitest'

// Zones come from the cluster-scoped Zone CRs (zones.auth.w6d.io) when the Kubernetes client is on,
// from SITES_ZONES otherwise. When the cluster cannot be read, nothing is guessed: 503.

vi.mock('../../services/redis-client.service.js', () => ({ getRedisClient: () => ({}) }))

import { zones, checkHost } from '../../sites/sites.service.js'
import { setKubeSites, KubeUnavailable, type KubeSites } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import { sitesRepository } from '../../sites/repository.js'
import { redisRbacRepository } from '../../services/redis-rbac.repository.js'

const kube = {
  up: true,
  ping: vi.fn(), get: vi.fn(), apply: vi.fn(), delete: vi.fn(), listIngresses: vi.fn(async () => []),
  listZones: vi.fn(async () => {
    if (!kube.up) throw new KubeUnavailable('down')
    return [
      { metadata: { name: 'apps' }, spec: { domain: 'apps.dev.stairling.com', ingressClass: 'nginx', tls: { mode: 'issuer' } } },
      { metadata: { name: 'fleet' }, spec: { domain: 'dev.stairfleet.com', tls: { mode: 'default' } } },
    ]
  }),
}

beforeEach(() => {
  kube.up = true
  process.env.SITES_ZONES = '[{"suffix":"dev.stairling.com"},{"suffix":"dev.stairfleet.com","cookieDomain":".stairfleet.com"}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.stairling.com'
  vi.spyOn(sitesRepository, 'list').mockResolvedValue([])
  vi.spyOn(redisRbacRepository, 'getAccessRules').mockResolvedValue([])
  setKubeSites(kube as unknown as KubeSites)
})

describe('zones', () => {
  it('falls back to SITES_ZONES when the Kubernetes client is off', async () => {
    process.env.SITES_KUBE = 'off'
    resetSitesConfig()
    expect((await zones()).map((z) => z.suffix)).toEqual(['dev.stairling.com', 'dev.stairfleet.com'])
    expect(kube.listZones).not.toHaveBeenCalled()
  })

  it('reads the Zone CRs when it is on; a cookie domain from SITES_ZONES still applies to the same domain', async () => {
    process.env.SITES_KUBE = 'in-cluster'
    resetSitesConfig()
    expect(await zones()).toEqual([
      { name: 'apps', suffix: 'apps.dev.stairling.com', wildcard: '*.apps.dev.stairling.com', cookieDomain: '.dev.stairling.com', sso: true, tls: 'wildcard', ingressClass: 'nginx', ingress: 'wildcard', source: 'zone' },
      { name: 'fleet', suffix: 'dev.stairfleet.com', wildcard: '*.dev.stairfleet.com', cookieDomain: '.stairfleet.com', sso: true, tls: 'wildcard', ingress: 'wildcard', source: 'zone' },
    ])
    expect(await checkHost({ host: 'shop.apps.dev.stairling.com' })).toMatchObject({ available: true, zone: 'apps.dev.stairling.com' })
    // Not a Zone CR any more, so not a zone — config does not add to the cluster's list.
    expect(await checkHost({ host: 'shop.dev.stairling.com' })).toMatchObject({ available: false, zone: null })
  })

  it('answers 503 rather than guessing when the Zone CRs cannot be read', async () => {
    process.env.SITES_KUBE = 'in-cluster'
    resetSitesConfig()
    kube.up = false
    await expect(zones()).rejects.toMatchObject({ statusCode: 503 })
    await expect(checkHost({ host: 'shop.apps.dev.stairling.com' })).rejects.toMatchObject({ statusCode: 503 })
  })
})
