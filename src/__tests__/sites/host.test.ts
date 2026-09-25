import { describe, it, expect } from 'vitest'
import { placeHost, zonesView } from '../../sites/host.js'

// Owner decision: zones are admin-defined wildcard domains. A host exactly one label under a zone is
// served with rules only (exposure `zone`); `vanity` (one Ingress) is opt-in. Outside every zone,
// or deeper than the wildcard reaches, the host is refused. SSO = the login cookie reaches the zone.

const zones = [
  { suffix: 'dev.example.com', wildcardTls: true },
  { suffix: 'authdev.dev.example.com', wildcardTls: true },
  { suffix: 'qualif.example.com', wildcardTls: false },
  { suffix: 'dev.stairfleet.com', wildcardTls: true, cookieDomain: '.stairfleet.com' },
]
const cookie = '.dev.example.com'

describe('placeHost', () => {
  it('one label under a zone: rules only, SSO when the cookie domain covers the zone', () => {
    expect(placeHost('shop.dev.example.com', zones, cookie)).toMatchObject({ zone: 'dev.example.com', tooDeep: false, sso: true, modes: ['zone', 'vanity'], tls: 'wildcard' })
  })

  it('the most specific zone wins', () => {
    expect(placeHost('shop.authdev.dev.example.com', zones, cookie)).toMatchObject({ zone: 'authdev.dev.example.com', sso: true })
  })

  it('a zone with its own cookie domain reports its own SSO coverage', () => {
    expect(placeHost('app.dev.stairfleet.com', zones, cookie)).toMatchObject({ zone: 'dev.stairfleet.com', sso: true, cookieDomain: '.stairfleet.com' })
  })

  it('a zone the login cookie does not reach has no SSO', () => {
    expect(placeHost('x.qualif.example.com', zones, cookie)).toMatchObject({ zone: 'qualif.example.com', sso: false, tls: 'per-site' })
  })

  it('deeper than one label is refused', () => {
    expect(placeHost('a.b.qualif.example.com', zones, cookie)).toMatchObject({ zone: null, tooDeep: true, modes: [] })
  })

  it('outside every zone is refused', () => {
    expect(placeHost('payroll.example.com', zones, cookie)).toMatchObject({ zone: null, tooDeep: false, sso: false, modes: [] })
  })
})

describe('zonesView', () => {
  it('lists each zone as a wildcard with its cookie domain and SSO coverage', () => {
    expect(zonesView(zones.slice(2), cookie)).toEqual([
      { suffix: 'qualif.example.com', wildcard: '*.qualif.example.com', cookieDomain: '.dev.example.com', sso: false, tls: 'per-site', source: 'config' },
      { suffix: 'dev.stairfleet.com', wildcard: '*.dev.stairfleet.com', cookieDomain: '.stairfleet.com', sso: true, tls: 'wildcard', source: 'config' },
    ])
  })
})
