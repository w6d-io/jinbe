/**
 * Where a host can live. Zones are admin-defined wildcard domains (`*.dev.stairling.com`, owner
 * decision): a host exactly one label under a zone is served with gateway rules only — the zone's
 * wildcard DNS, certificate and Ingress already reach the gateway (exposure `zone`). A `vanity`
 * exposure (one Ingress from the operator's fixed template) is opt-in for the same hosts.
 *
 * Outside every zone, or deeper than the wildcard reaches, a host is refused: the platform writes
 * neither DNS nor certificates for arbitrary names. SSO is whether the Kratos session cookie reaches
 * the zone. Pure: the zones come from configuration (SITES_ZONES).
 */

export interface Zone {
  /** The Zone CR name, when the zone comes from the cluster. */
  name?: string
  /** `dev.stairling.com` for the wildcard `*.dev.stairling.com` (Zone `spec.domain`). */
  suffix: string
  ingressClass?: string
  /** `zone`: a Zone CR (zones.auth.w6d.io); `config`: SITES_ZONES, used when the cluster is not read. */
  source?: 'zone' | 'config'
  /** Whether the zone's wildcard certificate is served (default true); false = a certificate per vanity site. */
  wildcardTls?: boolean
  /** The login cookie domain for this zone when it differs from the platform one. */
  cookieDomain?: string
}

export type ExposureMode = 'zone' | 'vanity'

export interface HostPlacement {
  zone: string | null
  /** Under a zone, but more than one label deep: the wildcard does not reach it. */
  tooDeep: boolean
  cookieDomain: string | null
  sso: boolean
  modes: ExposureMode[]
  tls: 'wildcard' | 'per-site' | 'none'
}

const bare = (domain: string) => domain.replace(/^\./, '').toLowerCase()
const under = (host: string, domain: string) => host === bare(domain) || host.endsWith(`.${bare(domain)}`)

function ssoOf(zone: Zone, platformCookieDomain: string | undefined) {
  const cookieDomain = zone.cookieDomain ?? platformCookieDomain ?? null
  return { cookieDomain, sso: !!cookieDomain && under(zone.suffix.toLowerCase(), cookieDomain) }
}

export function placeHost(host: string, zones: readonly Zone[], platformCookieDomain: string | undefined): HostPlacement {
  const h = host.toLowerCase()
  // The most specific zone wins (`authdev.dev.stairling.com` before `dev.stairling.com`).
  const zone = [...zones].sort((a, b) => b.suffix.length - a.suffix.length).find((z) => h.endsWith(`.${z.suffix.toLowerCase()}`))
  if (!zone) return { zone: null, tooDeep: false, cookieDomain: null, sso: false, modes: [], tls: 'none' }
  const { cookieDomain, sso } = ssoOf(zone, platformCookieDomain)
  const labels = h.slice(0, -(zone.suffix.length + 1)).split('.').length
  if (labels !== 1) return { zone: null, tooDeep: true, cookieDomain, sso, modes: [], tls: 'none' }
  return { zone: zone.suffix, tooDeep: false, cookieDomain, sso, modes: ['zone', 'vanity'], tls: zone.wildcardTls === false ? 'per-site' : 'wildcard' }
}

/** The zones as kuma shows them (`GET /api/admin/sites/zones`). */
export function zonesView(zones: readonly Zone[], platformCookieDomain: string | undefined) {
  return zones.map((z) => {
    const { cookieDomain, sso } = ssoOf(z, platformCookieDomain)
    return {
      ...(z.name ? { name: z.name } : {}),
      suffix: z.suffix,
      wildcard: `*.${z.suffix}`,
      cookieDomain,
      sso,
      tls: z.wildcardTls === false ? 'per-site' as const : 'wildcard' as const,
      ...(z.ingressClass ? { ingressClass: z.ingressClass } : {}),
      source: z.source ?? 'config',
    }
  })
}
