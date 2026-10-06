import { env } from '../config/env.js'
import type { Platform } from './render.js'
import type { Zone } from './host.js'
import { sitesConfig } from './config.js'
import { kubeSites, type ZoneCr, type ZoneCrObject } from './kube-sites.js'
import { currentSpec } from '../gateway/service.js'
import { PLATFORM_IDENTITY_HEADERS, decisionUrlOf, gatewayIdentity } from './identity-headers.js'

/**
 * What render needs to know about the platform: enabled handlers, namespace, zones.
 *
 * Zones are the cluster-scoped Zone CRs when the Kubernetes client is on — the same objects the
 * operator and admission check hosts against — and SITES_ZONES otherwise. The Zone CR carries no
 * cookie domain, so a SITES_ZONES entry for the same domain may still set one. When the cluster
 * cannot be read the caller gets 503; config is never silently substituted for the cluster.
 */
/**
 * Zone CRs are cluster-scoped, and one cluster may run several releases (auth-dev, auth-qualif): a
 * release sees only its OWN zones — the ones SITES_ZONES names (by suffix) and the ones it created
 * itself (labelled with its namespace, ZONE_OWNER_LABEL). Another release's Zone is not listed, not
 * found, not editable, and no site of this release may stand on it.
 */
export const ZONE_OWNER_LABEL = 'auth.w6d.io/zone-owner'

export function ownsZone(cr: Pick<ZoneCrObject | ZoneCr, 'metadata' | 'spec'>): boolean {
  const cfg = sitesConfig()
  return cfg.SITES_ZONES.some((z) => z.suffix === cr.spec.domain) || cr.metadata.labels?.[ZONE_OWNER_LABEL] === cfg.namespace
}

/** This release's Zone CRs (ownsZone). */
export async function ownZoneCrs(): Promise<ZoneCrObject[]> {
  return (await kubeSites().listZones()).filter(ownsZone)
}

/** What a refusal says this environment has: its zones' domains, or that it has none. */
export async function ownZoneDomains(): Promise<string> {
  const domains = (await loadZones()).map((z) => z.suffix)
  return domains.length > 0 ? domains.join(', ') : 'none configured'
}

export async function loadZones(): Promise<Zone[]> {
  const cfg = sitesConfig()
  const configured = cfg.SITES_ZONES.map((z) => ({ ...z, source: 'config' as const }))
  if (cfg.SITES_KUBE === 'off') return configured
  const crs = await ownZoneCrs()
  return crs.map((z) => ({
    name: z.metadata.name,
    suffix: z.spec.domain,
    // Every Zone TLS mode (default certificate, secret, issued) serves a wildcard certificate.
    wildcardTls: true,
    tlsMode: z.spec.tls?.mode ?? 'default',
    ingress: z.spec.ingress ?? 'wildcard',
    ...(z.spec.gateway ? { gateway: `${z.spec.gateway.namespace}/${z.spec.gateway.name}` } : {}),
    ...(z.spec.ingressClass ? { ingressClass: z.spec.ingressClass } : {}),
    ...(configured.find((c) => c.suffix === z.spec.domain)?.cookieDomain ? { cookieDomain: configured.find((c) => c.suffix === z.spec.domain)!.cookieDomain } : {}),
    source: 'zone' as const,
    ...readiness(z),
  }))
}

/** The Zone's Ready condition as the operator last wrote it for its current spec; nothing when unknown. */
function readiness(z: ZoneCrObject): { ready?: boolean } {
  const c = z.status?.conditions?.find((x) => x.type === 'Ready')
  if (!c || (z.status?.observedGeneration ?? 0) !== (z.metadata.generation ?? z.status?.observedGeneration)) return {}
  return { ready: c.status === 'True' }
}

/**
 * Identity headers: the platform's, plus what the gateway config sets from the session or forwards
 * from a decision. Read with the zones, and like them a cluster failure is the caller's 503 rather
 * than a silently shorter list (a different list renames the rules).
 */
async function loadIdentity(): Promise<Pick<Platform, 'identityHeaders' | 'authorizerHeaders' | 'decisionUrl' | 'templatedHeaders'>> {
  const cfg = sitesConfig()
  if (cfg.SITES_KUBE === 'off') {
    const url = decisionUrlOf(cfg.SITES_AUTHZ_DECISION_URL, undefined)
    return { identityHeaders: PLATFORM_IDENTITY_HEADERS, authorizerHeaders: {}, ...(url ? { decisionUrl: url } : {}) }
  }
  const gw = gatewayIdentity(await currentSpec())
  const url = decisionUrlOf(cfg.SITES_AUTHZ_DECISION_URL, gw.policyRemote)
  return {
    identityHeaders: [...new Set([...PLATFORM_IDENTITY_HEADERS, ...gw.headers, ...Object.values(gw.forwarded).flat()])],
    authorizerHeaders: gw.forwarded,
    templatedHeaders: gw.headers,
    ...(url ? { decisionUrl: url } : {}),
  }
}

export async function loadPlatform(): Promise<Platform> {
  const cfg = sitesConfig()
  return {
    namespace: cfg.namespace,
    enabled: {
      authenticators: env.OATHKEEPER_ENABLED_AUTHENTICATORS,
      authorizers: env.OATHKEEPER_ENABLED_AUTHORIZERS,
      mutators: env.OATHKEEPER_ENABLED_MUTATORS,
      errors: env.OATHKEEPER_ENABLED_ERROR_HANDLERS,
    },
    zones: await loadZones(),
    cookieDomain: cfg.SITES_COOKIE_DOMAIN,
    platformNamespaces: cfg.SITES_PLATFORM_NAMESPACES,
    upstreamAllow: cfg.SITES_UPSTREAM_ALLOW,
    ...(cfg.SITES_ACCESS_URL ? { accessUrl: cfg.SITES_ACCESS_URL } : {}),
    ...(cfg.SITES_ROLE_HEADERS ? { roleHeaders: true } : {}),
    ...(cfg.SITES_UPSTREAM_PATH ? { upstreamPath: true } : {}),
    ...(await loadIdentity()),
  }
}
