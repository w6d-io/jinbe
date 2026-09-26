import { env } from '../config/env.js'
import type { Platform } from './render.js'
import type { Zone } from './host.js'
import { sitesConfig } from './config.js'
import { kubeSites } from './kube-sites.js'

/**
 * What render needs to know about the platform: enabled handlers, namespace, zones.
 *
 * Zones are the cluster-scoped Zone CRs when the Kubernetes client is on — the same objects the
 * operator and admission check hosts against — and SITES_ZONES otherwise. The Zone CR carries no
 * cookie domain, so a SITES_ZONES entry for the same domain may still set one. When the cluster
 * cannot be read the caller gets 503; config is never silently substituted for the cluster.
 */
export async function loadZones(): Promise<Zone[]> {
  const cfg = sitesConfig()
  const configured = cfg.SITES_ZONES.map((z) => ({ ...z, source: 'config' as const }))
  if (cfg.SITES_KUBE === 'off') return configured
  const crs = await kubeSites().listZones()
  return crs.map((z) => ({
    name: z.metadata.name,
    suffix: z.spec.domain,
    // Every Zone TLS mode (default certificate, secret, issued) serves a wildcard certificate.
    wildcardTls: true,
    ...(z.spec.ingressClass ? { ingressClass: z.spec.ingressClass } : {}),
    ...(configured.find((c) => c.suffix === z.spec.domain)?.cookieDomain ? { cookieDomain: configured.find((c) => c.suffix === z.spec.domain)!.cookieDomain } : {}),
    source: 'zone' as const,
  }))
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
    ...(cfg.SITES_ACCESS_URL ? { accessUrl: cfg.SITES_ACCESS_URL } : {}),
  }
}
