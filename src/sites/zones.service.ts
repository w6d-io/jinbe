import { createHash } from 'node:crypto'
import { auditZone } from '../audit/record.js'
import type { Actor } from './audit.js'
import { siteError } from './checks.js'
import { sitesConfig } from './config.js'
import { probeHost, probeWildcard, type DnsReport } from './dns-probe.js'
import { placeHost, ssoOf, type Zone } from './host.js'
import { kubeSites, KubeRefused, type IngressHosts, type SiteCondition, type ZoneCr, type ZoneCrObject, type ZoneGatewayRef, type ZoneIngressMode } from './kube-sites.js'
import { clusterIngresses, collisionChecks, wildcardConflicts, type IngressRef } from './host-collisions.js'
import { coveringListener, gatewayView, listGateways, type GatewayView } from './gateways.service.js'
import { anyProtected, defaultGateway, protectionFor, type ProtectionStatus } from './protection.js'
import { ZONE_OWNER_LABEL, loadZones, ownZoneCrs, ownZoneDomains, ownsZone } from './platform.js'
import { sitesRepository, type SiteRecord } from './repository.js'
import { liveAddresses } from './address.js'
import type { CreateZoneBody, UpdateZoneBody } from './schemas.js'

/**
 * Zones from kuma ("Plug a site" → "Create zone"): read one, create, delete, and suggest the zone a
 * host outside every zone would need.
 *
 * jinbe writes the Zone CR's spec only; site-operator reconciles it into the wildcard Ingress (and a
 * Certificate for mode issuer), or with a gateway into one HTTPRoute per host on that Gateway (Envoy,
 * behind its WAF), and mirrors the domain into the admission policy's ConfigMap. A zone moves from
 * the Ingress to the Gateway in three edits: attach the gateway, move DNS, then `ingress: none`. What
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

/** One site host's DNS against the Gateway, as a check (the report of a move to `ingress: none`). */
const dnsHostCheck = (d: DnsReport) => ({
  level: d.status === 'ok' ? 'info' as const : d.status === 'unverified' ? 'warn' as const : 'error' as const,
  code: `dns_${d.status}`, message: d.message, host: d.probe, addresses: d.addresses,
})

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
    /**
     * The Gateways the zone may be attached to (SITES_GATEWAYS). `suggested` is the default: the first
     * one with the WAF in force that can serve the zone; null = none, the zone falls back to nginx.
     */
    gateway: { options: string[]; suggested: string | null }
    /** What the suggested exposure gives the zone: behind the WAF, or not. */
    protection: ProtectionStatus
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
  const gateways = cfg.SITES_KUBE === 'off' ? [] : (await listGateways()).gateways
  const best = defaultGateway(gateways, domain, 'default') ?? defaultGateway(gateways, domain, 'issuer')
  const protection = protectionFor(best ? { ingress: 'none', gateway: best.key } : { ingress: 'wildcard' }, gateways)
  if (best) checks.push(...wild.checks.map((c) => ({ ...c, level: 'info' as const })))
  else {
    checks.push(...wild.checks)
    if (parent) checks.push(noWafCheck(null))
  }
  const tlsSuggested = best && !coveringListener(best, domain) ? 'issuer' : cfg.SITES_ZONE_ISSUERS.length > 0 ? 'issuer' : 'default'
  return {
    host: h,
    covered: false,
    domain,
    name: zoneNameFor(domain),
    wildcard: `*.${domain}`,
    allowed: !!parent,
    allowedParents: cfg.SITES_ZONE_ALLOWED_PARENTS,
    dns,
    tls: { modes: ['default', 'issuer', 'secret'], issuers: cfg.SITES_ZONE_ISSUERS, suggested: best ? (coveringListener(best, domain) ? 'default' : 'issuer') : tlsSuggested },
    ingress: { modes: cfg.SITES_GATEWAYS.length ? ['wildcard', 'per-site', 'none'] : ['wildcard', 'per-site'], suggested: best ? 'none' : wild.shared?.length ? 'per-site' : 'wildcard', shared: wild.shared },
    gateway: { options: cfg.SITES_GATEWAYS, suggested: best?.key ?? null },
    protection,
    cookieDomain,
    sso,
    checks,
  }
}

export async function suggestZone(host: string): Promise<ZoneSuggestion> {
  return suggestFor(host, await loadZones())
}

/**
 * Sites whose host the zone serves (the most specific zone wins, as for placement): the saved host,
 * and the host an applied site still serves until a saved move is applied (`live`).
 */
function sitesOn(domain: string, zones: readonly Zone[], records: readonly SiteRecord[], live?: Map<string, SiteRecord['site']['address']>) {
  const on = (host: string) => placeHost(host, zones, undefined).zone === domain
  return records
    .flatMap((r) => {
      const held = live?.get(r.site.name)?.host
      const host = on(r.site.address.host) ? r.site.address.host : held && on(held) ? held : null
      return host ? [{ name: r.site.name, host, applied: !!r.applied }] : []
    })
    .sort((a, b) => a.name.localeCompare(b.name))
}

const conditionOf = (z: ZoneCrObject, type: string) => {
  const c: SiteCondition | undefined = z.status?.conditions?.find((x) => x.type === type)
  return c ? { status: c.status, reason: c.reason ?? '', message: c.message ?? '', ...(c.lastTransitionTime ? { since: c.lastTransitionTime } : {}) } : null
}

const keyOf = (g: ZoneGatewayRef) => `${g.namespace}/${g.name}`

/**
 * How the zone is reached: `entry` (the nginx Ingress, the Gateway, or both while it migrates) and
 * `wafBypass` (an Ingress still answers: anyone can reach the hosts without the WAF).
 */
function exposureOf(cr: ZoneCrObject) {
  const ingress = (cr.spec.ingress ?? 'wildcard') !== 'none'
  const gateway = !!cr.spec.gateway
  return {
    entry: gateway && ingress ? 'both' as const : gateway ? 'gateway' as const : 'ingress' as const,
    wafBypass: ingress,
  }
}

/** The zone's protection from its spec and the Gateways discovered (`protection.ts`). */
export function zoneProtection(spec: ZoneCrObject['spec'], gateways: readonly GatewayView[]): ProtectionStatus {
  return protectionFor({ ingress: spec.ingress, ...(spec.gateway ? { gateway: keyOf(spec.gateway) } : {}) }, gateways)
}

/** The warning of a zone left without WAF: chosen while a protected Gateway exists, or none exists. */
function noWafCheck(available: GatewayView | null): Check {
  return available
    ? { level: 'warn', code: 'no_waf', message: `Chosen without WAF: Gateway ${available.key} would inspect this zone with its WAF, but it is served by the nginx Ingress (no WAF, no IP bans)` }
    : { level: 'warn', code: 'no_waf', message: 'No WAF-protected Gateway was found in the cluster: this zone is served by the nginx Ingress, without WAF or IP bans' }
}

function zoneView(cr: ZoneCrObject, sites: ReturnType<typeof sitesOn>, gateways: readonly GatewayView[] = []) {
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
    gateway: cr.spec.gateway ?? null,
    exposure: exposureOf(cr),
    protection: zoneProtection(cr.spec, gateways),
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
      gateway: conditionOf(cr, 'GatewayReady'),
      certificate: conditionOf(cr, 'CertificateReady'),
      validated,
      domainTaken: validated?.reason === 'DomainTaken',
      message: ready?.message ?? (observed ? '' : 'waiting for the operator'),
    },
    sites,
  }
}

/** A Zone CR of this release by name; another release's (cluster-scoped, same API) is not found here. */
async function ownZone(name: string): Promise<ZoneCrObject> {
  const cr = await kubeSites().getZone(name)
  if (!cr || !ownsZone(cr)) throw siteError(404, 'not_found', `Zone not found: ${name} (this environment's zones: ${await ownZoneDomains()})`)
  return cr
}

export async function getZone(name: string) {
  const cr = await ownZone(name)
  const zones = await loadZones()
  const records = await sitesRepository.list()
  const gw = cr.spec.gateway && sitesConfig().SITES_GATEWAYS.includes(keyOf(cr.spec.gateway)) ? [await gatewayView(keyOf(cr.spec.gateway))] : []
  return zoneView(cr, sitesOn(cr.spec.domain, zones, records, await liveAddresses(records)), gw)
}

/**
 * A gateway a zone is being attached to: allowed here, existing, and — for TLS `default` — with an
 * HTTPS listener for exactly `*.<domain>` (else the operator reports ListenerDoesNotCover).
 */
async function checkGateway(ref: ZoneGatewayRef, domain: string, tlsMode: string): Promise<GatewayView> {
  const gw = await gatewayView(keyOf(ref))
  if (!gw.exists) throw siteError(422, 'gateway_not_found', gw.message)
  if (tlsMode === 'default' && !coveringListener(gw, domain, ref.sectionName)) {
    throw siteError(422, 'listener_not_covering', `Gateway ${gw.key} has no HTTPS listener${ref.sectionName ? ` named ${ref.sectionName}` : ''} for *.${domain}; choose TLS issuer or secret to bring the zone's own listener (ListenerSet)`)
  }
  return gw
}

export async function createZone(body: CreateZoneBody, actor: Actor) {
  const cfg = sitesConfig()
  if (!allowedParentOf(body.domain, cfg.SITES_ZONE_ALLOWED_PARENTS)) {
    throw siteError(422, 'zone_not_allowed', `${body.domain} is not under a domain this platform serves (${cfg.SITES_ZONE_ALLOWED_PARENTS.join(', ') || 'none configured'})`)
  }
  if (body.tls.mode === 'issuer' && body.tls.issuer && !cfg.SITES_ZONE_ISSUERS.includes(body.tls.issuer)) {
    throw siteError(422, 'issuer_not_allowed', `issuer ${body.tls.issuer} is not offered here (${cfg.SITES_ZONE_ISSUERS.join(', ') || 'operator default only'})`)
  }
  // Domains are unique cluster-wide (the operator's DomainTaken): another release's zone counts too.
  const crs = await kubeSites().listZones()
  const same = crs.find((z) => z.spec.domain === body.domain)
  if (same && ownsZone(same)) throw siteError(409, 'zone_exists', `*.${body.domain} is already zone ${same.metadata.name}`)
  if (same) throw siteError(409, 'zone_taken', `*.${body.domain} is already zone ${same.metadata.name} of another environment on this cluster; this environment's zones: ${await ownZoneDomains()}`)
  // WAF by default (owner decision 2026-09-28): with neither a gateway nor an ingress mode asked, the
  // zone goes on the first WAF-protected Gateway that can serve it, without an Ingress. The nginx
  // Ingress is the fallback when there is none; choosing it while there is one must be explicit.
  const gateways = (await listGateways()).gateways
  const auto = !body.gateway && !body.ingress ? defaultGateway(gateways, body.domain, body.tls.mode) : null
  const ref = body.gateway ?? (auto ? { namespace: auto.namespace, name: auto.name } : undefined)
  const available = anyProtected(gateways)
  if (!ref && available && !body.acknowledgeNoWaf) {
    const hint = !body.gateway && body.tls.mode === 'default' && !coveringListener(available, body.domain) ? ` (it has no listener for *.${body.domain}: choose TLS issuer so the zone brings its own)` : ''
    throw siteError(409, 'waf_available', `Gateway ${available.key} would put *.${body.domain} behind the WAF${hint}; creating it on the nginx Ingress leaves it without WAF or IP bans. Choose the gateway, or confirm the choice (acknowledgeNoWaf)`)
  }
  const gw = ref ? await checkGateway(ref, body.domain, body.tls.mode) : null

  // A wildcard next to another one for the same domain collides; exact hosts it would shadow are a warning.
  const ingress = body.ingress ?? (auto ? 'none' : 'wildcard')
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
    // Owned by this release (its namespace): listed, editable and usable here only.
    metadata: { name, labels: { ...MANAGED_BY, [ZONE_OWNER_LABEL]: cfg.namespace } },
    spec: { domain: body.domain, ingress, ...(body.ingressClass ? { ingressClass: body.ingressClass } : {}), tls, ...(ref ? { gateway: ref } : {}) },
  }
  try {
    await kubeSites().createZone(cr)
  } catch (err) {
    if (err instanceof KubeRefused) throw siteError(err.statusCode, err.code, err.message)
    throw err
  }
  const protection = zoneProtection(cr.spec, gateways)
  auditZone('create', name, actor, {
    domain: body.domain, ingress, tls: tls.mode, issuer: body.tls.issuer, ingressClass: body.ingressClass, gateway: gw?.key,
    protection: protection.state, ...(!gw && available ? { wafOptOut: true, wafAvailable: available.key } : {}),
  })
  const checks: Check[] = [...wild.checks]
  if (!gw) checks.push(noWafCheck(available))
  else if (!gw.protection.protected) checks.push({ level: 'warn', code: 'gateway_not_protected', message: `Gateway ${gw.key}: ${gw.protection.summary}` })
  const dns = await probeWildcard(body.domain, ingress === 'none' && gw ? gw.addresses : platformIngress(crs))
  return { ...zoneView({ ...cr, metadata: { name } }, [], gateways), dns, checks }
}

/**
 * Change a zone's exposure in place (Settings → Zones → Edit): the ingress mode, the gateway, TLS.
 * Dropping the Ingress (`ingress: none`) first asks DNS: a site host still resolving away from the
 * Gateway would lose its visitors, so it is refused (409 `dns_not_on_gateway`, with the per-host
 * report) unless `confirm` says the move is known. The domain and the sites do not change: the
 * operator keeps every Rule and swaps only the entry points, the new one before the old goes.
 */
export async function updateZone(name: string, body: UpdateZoneBody, actor: Actor) {
  const kube = kubeSites()
  if (!kube.updateZone) throw siteError(503, 'kubernetes_unavailable', 'Zones cannot be changed on this server')
  const cr = await ownZone(name)
  const before = cr.spec
  const spec: ZoneCrObject['spec'] = { ...before }
  if (body.ingress !== undefined) spec.ingress = body.ingress
  if (body.gateway === null) delete spec.gateway
  else if (body.gateway !== undefined) spec.gateway = body.gateway
  if (body.tls !== undefined) spec.tls = { mode: body.tls.mode, ...(body.tls.issuer ? { issuer: body.tls.issuer } : {}), ...(body.tls.secretName ? { secretName: body.tls.secretName } : {}) }
  if (body.ingressClass === null) delete spec.ingressClass
  else if (body.ingressClass !== undefined) spec.ingressClass = body.ingressClass

  const cfg = sitesConfig()
  const ingress = spec.ingress ?? 'wildcard'
  const was = before.ingress ?? 'wildcard'
  if (ingress === 'none' && !spec.gateway) throw siteError(422, 'no_entry_point', 'ingress none needs a gateway: a zone needs an entry point')
  if (body.tls?.mode === 'issuer' && body.tls.issuer && !cfg.SITES_ZONE_ISSUERS.includes(body.tls.issuer)) {
    throw siteError(422, 'issuer_not_allowed', `issuer ${body.tls.issuer} is not offered here (${cfg.SITES_ZONE_ISSUERS.join(', ') || 'operator default only'})`)
  }
  const gw = spec.gateway ? await checkGateway(spec.gateway, spec.domain, spec.tls?.mode ?? 'default') : null
  const gateways = (await listGateways()).gateways
  // Detaching the Gateway while a WAF-protected one exists is an explicit, audited choice.
  const available = anyProtected(gateways)
  const optOut = body.gateway === null && !!before.gateway && !!available
  if (optOut && !body.acknowledgeNoWaf) {
    throw siteError(409, 'waf_available', `Detaching the Gateway leaves *.${spec.domain} on the nginx Ingress without WAF or IP bans while Gateway ${available!.key} could protect it; confirm the choice (acknowledgeNoWaf)`)
  }
  const checks: Check[] = []
  if (!gw) checks.push(noWafCheck(available))
  if (gw && !gw.protection.protected) checks.push({ level: 'warn', code: 'gateway_not_protected', message: `Gateway ${gw.key}: ${gw.protection.summary}` })
  if (ingress === 'wildcard' && was !== 'wildcard') {
    const taken = wildcardChecks(spec.domain, (await clusterIngresses()) ?? []).checks.find((c) => c.code === 'wildcard_taken')
    if (taken) throw siteError(409, 'wildcard_taken', taken.message)
  }

  // Dropping the Ingress: every site host must already resolve to the Gateway.
  let dns: DnsReport[] = []
  if (ingress === 'none' && was !== 'none' && gw) {
    const records = await sitesRepository.list()
    const hosts = [...new Set(sitesOn(spec.domain, await loadZones(), records, await liveAddresses(records)).map((x) => x.host))]
    dns = await Promise.all(hosts.map((h) => probeHost(h, gw.addresses, `Gateway ${gw.key}`)))
    const away = dns.filter((d) => d.status === 'elsewhere' || d.status === 'unresolved')
    if (away.length > 0 && !body.confirm) {
      throw Object.assign(
        siteError(409, 'dns_not_on_gateway', `${away.length} site host(s) do not resolve to Gateway ${gw.key} yet (${away.map((d) => d.probe).join(', ')}); move their DNS first, or confirm to drop the Ingress anyway`),
        { checks: dns.map(dnsHostCheck) },
      )
    }
  }

  try {
    await kube.updateZone({ ...cr, spec })
  } catch (err) {
    if (err instanceof KubeRefused) throw siteError(err.statusCode, err.code, err.message)
    throw err
  }
  const protection = zoneProtection(spec, gateways)
  auditZone('update', name, actor, {
    domain: spec.domain, ingress, tls: spec.tls?.mode ?? 'default', issuer: spec.tls?.issuer, ingressClass: spec.ingressClass,
    gateway: gw?.key, from: `ingress ${was}${before.gateway ? `, gateway ${keyOf(before.gateway)}` : ''}`,
    protection: protection.state, ...(optOut ? { wafOptOut: true, wafAvailable: available!.key } : {}),
  })
  return { ...zoneView({ ...cr, spec }, [], gateways), checks: [...checks, ...dns.map(dnsHostCheck)] }
}

export async function deleteZone(name: string, actor: Actor) {
  const cr = await ownZone(name)
  // A duplicate Zone (DomainTaken) serves nothing its older twin does not: removing it strands no site.
  // Only a twin of this release counts: another release's would not serve this one's sites.
  const twin = (await ownZoneCrs()).some((z) => z.metadata.name !== name && z.spec.domain === cr.spec.domain)
  const records = twin ? [] : await sitesRepository.list()
  const using = twin ? [] : sitesOn(cr.spec.domain, await loadZones(), records, await liveAddresses(records))
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
