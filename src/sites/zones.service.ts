import { createHash } from 'node:crypto'
import { auditZone } from '../audit/record.js'
import type { Actor } from './audit.js'
import { siteError } from './checks.js'
import { sitesConfig } from './config.js'
import { probeWildcard, type DnsReport } from './dns-probe.js'
import { placeHost, ssoOf, type Zone } from './host.js'
import { kubeSites, KubeRefused, type IngressHosts, type SiteCondition, type ZoneCr, type ZoneCrObject, type ZoneIngressMode } from './kube-sites.js'
import { clusterIngresses, collisionChecks, wildcardConflicts, type IngressRef } from './host-collisions.js'
import { loadZones } from './platform.js'
import { sitesRepository, type SiteRecord } from './repository.js'
import type { CreateZoneBody } from './schemas.js'

/**
 * Zones from kuma ("Plug a site" → "Create zone"): read one, create, delete, and suggest the zone a
 * host outside every zone would need.
 *
 * jinbe writes the Zone CR's spec only; site-operator reconciles it into the wildcard Ingress (and a
 * Certificate for mode issuer) and mirrors the domain into the admission policy's ConfigMap. What
 * jinbe adds is what the cluster cannot know: which parent domains this platform may serve
 * (SITES_ZONE_ALLOWED_PARENTS), which issuers it offers, whether the wildcard DNS is in place, whether
 * the login cookie reaches the zone, and which Sites stand on a zone before it is deleted.
 */

const MANAGED_BY = { 'app.kubernetes.io/managed-by': 'jinbe' }

/** The Zone name for a domain: `apps.stairfleet.com` → `apps-stairfleet-com`, hashed down to 50. */
export function zoneNameFor(domain: string): string {
  const flat = domain.replace(/\./g, '-')
  if (flat.length <= 50) return flat
  const hash = createHash('sha256').update(domain).digest('hex').slice(0, 8)
  return `${flat.slice(0, 41).replace(/-+$/, '')}-${hash}`
}

/** The allowed parent a domain is at or under, or null. */
export function allowedParentOf(domain: string, parents: readonly string[]): string | null {
  return parents.find((p) => domain === p || domain.endsWith(`.${p}`)) ?? null
}

/**
 * The platform ingress: SITES_INGRESS_ADDRESSES, else the load balancers existing Zones were admitted
 * on (their IngressReady message, `load balancer <address>`).
 */
function platformIngress(crs: readonly ZoneCrObject[]): string[] {
  const configured = sitesConfig().SITES_INGRESS_ADDRESSES
  if (configured.length > 0) return configured
  const seen = crs.flatMap((z) => {
    const c = z.status?.conditions?.find((x) => x.type === 'IngressReady' && x.status === 'True')
    const m = c?.message?.match(/^load balancer (\S+)$/)
    return m ? [m[1]] : []
  })
  return [...new Set(seen)]
}

/** The Zone CRs, or [] when the cluster is not read (SITES_KUBE=off: zones come from config). */
async function zoneCrs(): Promise<ZoneCrObject[]> {
  return sitesConfig().SITES_KUBE === 'off' ? [] : kubeSites().listZones()
}

/** SSO for a domain: the cookie of the closest SITES_ZONES entry at or above it, else the platform's. */
function cookieFor(domain: string) {
  const cfg = sitesConfig()
  const cookieDomain = cfg.SITES_ZONES
    .filter((z) => z.cookieDomain && (domain === z.suffix || domain.endsWith(`.${z.suffix}`)))
    .sort((a, b) => b.suffix.length - a.suffix.length)[0]?.cookieDomain
  return ssoOf({ suffix: domain, ...(cookieDomain ? { cookieDomain } : {}) }, cfg.SITES_COOKIE_DOMAIN)
}

type Check = { level: 'error' | 'warn' | 'info'; code: string; message: string; ingress?: IngressRef }

function dnsCheck(dns: DnsReport): Check | null {
  if (dns.status === 'ok') return null
  return { level: dns.status === 'unverified' ? 'info' : 'warn', code: `dns_${dns.status}`, message: dns.message }
}

export type ZoneSuggestion =
  | { host: string; covered: true; zone: string }
  | {
    host: string
    covered: false
    /** The zone to create: the host's parent domain, one label up. */
    domain: string
    name: string
    wildcard: string
    /** Whether this platform may serve the domain (SITES_ZONE_ALLOWED_PARENTS). */
    allowed: boolean
    allowedParents: string[]
    /** Wildcard DNS probe; null when the domain is not allowed (nothing to probe for). */
    dns: DnsReport | null
    tls: { modes: Array<'default' | 'issuer' | 'secret'>; issuers: string[]; suggested: 'default' | 'issuer' }
    /**
     * per-site when other Ingresses already use the domain (`shared`): a wildcard would collide with
     * or shadow them. Null `shared` = the cluster's Ingresses were not read.
     */
    ingress: { modes: ZoneIngressMode[]; suggested: ZoneIngressMode; shared: IngressRef[] | null }
    cookieDomain: string | null
    sso: boolean
    checks: Check[]
  }

const list = (refs: IngressRef[]) => refs.map((r) => `${r.namespace}/${r.name} (${r.rule})`).join(', ')

/** Checks for a new wildcard over `domain`; mode per-site makes them moot. */
function wildcardChecks(domain: string, ingresses: readonly IngressHosts[]): { checks: Check[]; shared: IngressRef[] } {
  const { taken, shadowed } = wildcardConflicts(domain, ingresses)
  const checks: Check[] = []
  if (taken.length) checks.push({ level: 'warn', code: 'wildcard_taken', message: `*.${domain} is already served by ${list(taken)}; a wildcard zone would collide with it — use per-site` })
  if (shadowed.length) checks.push({ level: 'warn', code: 'wildcard_shadows', message: `${shadowed.length} host(s) under ${domain} already have their own Ingress (${list(shadowed)}); a wildcard zone would answer every other name — per-site is suggested` })
  return { checks, shared: [...taken, ...shadowed] }
}

/**
 * The zone a host needs, from the zones already loaded. `ingresses` are the cluster's (undefined:
 * read them here; null: not read, SITES_KUBE=off).
 */
export async function suggestFor(
  host: string,
  zones: readonly Zone[],
  opts: { crs?: readonly ZoneCrObject[]; ingresses?: readonly IngressHosts[] | null } = {},
): Promise<ZoneSuggestion> {
  const crs = opts.crs
  const cfg = sitesConfig()
  const h = host.toLowerCase()
  const placed = placeHost(h, zones, cfg.SITES_COOKIE_DOMAIN)
  if (placed.zone) return { host: h, covered: true, zone: placed.zone }

  const domain = h.split('.').slice(1).join('.')
  const parent = domain.includes('.') ? allowedParentOf(domain, cfg.SITES_ZONE_ALLOWED_PARENTS) : null
  const { cookieDomain, sso } = cookieFor(domain)
  const checks: Check[] = []
  let dns: DnsReport | null = null
  if (!parent) {
    checks.push({
      level: 'error',
      code: 'zone_not_allowed',
      message: cfg.SITES_ZONE_ALLOWED_PARENTS.length === 0
        ? 'No zone can be created from the console on this platform (SITES_ZONE_ALLOWED_PARENTS is empty)'
        : `${domain} is not under a domain this platform serves (${cfg.SITES_ZONE_ALLOWED_PARENTS.join(', ')})`,
    })
  } else {
    dns = await probeWildcard(domain, platformIngress(crs ?? (await zoneCrs())))
    const d = dnsCheck(dns)
    if (d) checks.push(d)
  }
  if (!sso) checks.push({ level: 'warn', code: 'no_sso', message: 'The login cookie does not reach this zone; browser sign-in will not work there' })
  const ingresses = opts.ingresses === undefined ? await clusterIngresses() : opts.ingresses
  // The host itself already answered by another Ingress: no zone would give it to a site.
  checks.unshift(...collisionChecks(h, undefined, ingresses).map(({ path: _p, ...c }) => c))
  const wild = ingresses && parent ? wildcardChecks(domain, ingresses) : { checks: [], shared: ingresses ? [] : null }
  checks.push(...wild.checks)
  return {
    host: h,
    covered: false,
    domain,
    name: zoneNameFor(domain),
    wildcard: `*.${domain}`,
    allowed: !!parent,
    allowedParents: cfg.SITES_ZONE_ALLOWED_PARENTS,
    dns,
    tls: { modes: ['default', 'issuer', 'secret'], issuers: cfg.SITES_ZONE_ISSUERS, suggested: cfg.SITES_ZONE_ISSUERS.length > 0 ? 'issuer' : 'default' },
    ingress: { modes: ['wildcard', 'per-site'], suggested: wild.shared?.length ? 'per-site' : 'wildcard', shared: wild.shared },
    cookieDomain,
    sso,
    checks,
  }
}

export async function suggestZone(host: string): Promise<ZoneSuggestion> {
  return suggestFor(host, await loadZones())
}

/** Saved Sites whose host the zone serves (the most specific zone wins, as for placement). */
function sitesOn(domain: string, zones: readonly Zone[], records: readonly SiteRecord[]) {
  return records
    .filter((r) => placeHost(r.site.address.host, zones, undefined).zone === domain)
    .map((r) => ({ name: r.site.name, host: r.site.address.host, applied: !!r.applied }))
    .sort((a, b) => a.name.localeCompare(b.name))
}

const conditionOf = (z: ZoneCrObject, type: string) => {
  const c: SiteCondition | undefined = z.status?.conditions?.find((x) => x.type === type)
  return c ? { status: c.status, reason: c.reason ?? '', message: c.message ?? '', ...(c.lastTransitionTime ? { since: c.lastTransitionTime } : {}) } : null
}

function zoneView(cr: ZoneCrObject, sites: ReturnType<typeof sitesOn>) {
  const { cookieDomain, sso } = cookieFor(cr.spec.domain)
  const validated = conditionOf(cr, 'Validated')
  const ready = conditionOf(cr, 'Ready')
  const observed = !!cr.status && cr.status.observedGeneration === (cr.metadata.generation ?? cr.status.observedGeneration)
  return {
    name: cr.metadata.name,
    domain: cr.spec.domain,
    wildcard: `*.${cr.spec.domain}`,
    ingress: cr.spec.ingress ?? 'wildcard',
    ingressClass: cr.spec.ingressClass ?? null,
    tls: {
      mode: cr.spec.tls?.mode ?? 'default',
      ...(cr.spec.tls?.issuer ? { issuer: cr.spec.tls.issuer } : {}),
      ...(cr.spec.tls?.secretName ? { secretName: cr.spec.tls.secretName } : {}),
    },
    cookieDomain,
    sso,
    createdAt: cr.metadata.creationTimestamp ?? null,
    status: {
      /** False until the operator has reconciled this generation. */
      observed,
      ready: observed && ready?.status === 'True',
      ingress: conditionOf(cr, 'IngressReady'),
      certificate: conditionOf(cr, 'CertificateReady'),
      validated,
      domainTaken: validated?.reason === 'DomainTaken',
      message: ready?.message ?? (observed ? '' : 'waiting for the operator'),
    },
    sites,
  }
}

export async function getZone(name: string) {
  const cr = await kubeSites().getZone(name)
  if (!cr) throw siteError(404, 'not_found', `Zone not found: ${name}`)
  const zones = await loadZones()
  return zoneView(cr, sitesOn(cr.spec.domain, zones, await sitesRepository.list()))
}

export async function createZone(body: CreateZoneBody, actor: Actor) {
  const cfg = sitesConfig()
  if (!allowedParentOf(body.domain, cfg.SITES_ZONE_ALLOWED_PARENTS)) {
    throw siteError(422, 'zone_not_allowed', `${body.domain} is not under a domain this platform serves (${cfg.SITES_ZONE_ALLOWED_PARENTS.join(', ') || 'none configured'})`)
  }
  if (body.tls.mode === 'issuer' && body.tls.issuer && !cfg.SITES_ZONE_ISSUERS.includes(body.tls.issuer)) {
    throw siteError(422, 'issuer_not_allowed', `issuer ${body.tls.issuer} is not offered here (${cfg.SITES_ZONE_ISSUERS.join(', ') || 'operator default only'})`)
  }
  const crs = await kubeSites().listZones()
  const same = crs.find((z) => z.spec.domain === body.domain)
  if (same) throw siteError(409, 'zone_exists', `*.${body.domain} is already zone ${same.metadata.name}`)

  // A wildcard next to another one for the same domain collides; exact hosts it would shadow are a warning.
  const ingress = body.ingress ?? 'wildcard'
  const wild = ingress === 'wildcard' ? wildcardChecks(body.domain, (await clusterIngresses()) ?? []) : { checks: [], shared: [] }
  const taken = wild.checks.find((c) => c.code === 'wildcard_taken')
  if (taken) throw siteError(409, 'wildcard_taken', taken.message)

  const name = body.name ?? zoneNameFor(body.domain)
  const tls = {
    mode: body.tls.mode,
    ...(body.tls.issuer ? { issuer: body.tls.issuer } : {}),
    ...(body.tls.secretName ? { secretName: body.tls.secretName } : {}),
  }
  const cr: ZoneCr = {
    apiVersion: 'auth.w6d.io/v1alpha1',
    kind: 'Zone',
    metadata: { name, labels: MANAGED_BY },
    spec: { domain: body.domain, ingress, ...(body.ingressClass ? { ingressClass: body.ingressClass } : {}), tls },
  }
  try {
    await kubeSites().createZone(cr)
  } catch (err) {
    if (err instanceof KubeRefused) throw siteError(err.statusCode, err.code, err.message)
    throw err
  }
  auditZone('create', name, actor, { domain: body.domain, ingress, tls: tls.mode, issuer: body.tls.issuer, ingressClass: body.ingressClass })
  const dns = await probeWildcard(body.domain, platformIngress(crs))
  return { ...zoneView({ ...cr, metadata: { name } }, []), dns, checks: wild.checks }
}

export async function deleteZone(name: string, actor: Actor) {
  const cr = await kubeSites().getZone(name)
  if (!cr) throw siteError(404, 'not_found', `Zone not found: ${name}`)
  // A duplicate Zone (DomainTaken) serves nothing its older twin does not: removing it strands no site.
  const twin = (await kubeSites().listZones()).some((z) => z.metadata.name !== name && z.spec.domain === cr.spec.domain)
  const using = twin ? [] : sitesOn(cr.spec.domain, await loadZones(), await sitesRepository.list())
  if (using.length > 0) {
    throw Object.assign(
      siteError(409, 'zone_in_use', `*.${cr.spec.domain} still serves ${using.length} site(s): ${using.map((s) => s.name).join(', ')}; move or delete them first`),
      { sites: using },
    )
  }
  await kubeSites().deleteZone(name)
  auditZone('delete', name, actor, { domain: cr.spec.domain, ingress: cr.spec.ingress ?? 'wildcard', tls: cr.spec.tls?.mode ?? 'default' })
  return { name, domain: cr.spec.domain, deleted: true }
}
