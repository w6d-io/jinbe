import { readFileSync } from 'node:fs'
import { z } from 'zod'
import type { Zone } from './host.js'

/**
 * Configuration of the Sites module, read from the environment on first use.
 *
 *   GATEKIT_URL            gatekit base URL. Unset = checks unavailable = preview/apply answer 503.
 *   GATEKIT_TIMEOUT_MS     per call (default 2000).
 *   SITES_KUBE             in-cluster | kubeconfig | off (default off = apply/pause/delete answer 503).
 *   SITES_NAMESPACE        where Site CRs live (default: the pod's namespace, else "auth").
 *   SITES_ZONES            JSON [{suffix, wildcardTls?, cookieDomain?}] — admin-defined wildcard
 *                          zones; a site host must be exactly one label under one.
 *   SITES_COOKIE_DOMAIN    Kratos session cookie domain (e.g. .dev.stairling.com): SSO coverage.
 *   SITES_PLATFORM_NAMESPACES  comma-separated namespaces no site upstream may point into.
 *   SITES_RESERVED_HOSTS   comma-separated platform hosts no site may take (kuma, login, auth…).
 */

const zoneSchema = z.object({
  suffix: z.string().regex(/^([a-z0-9-]+\.)+[a-z]{2,63}$/),
  wildcardTls: z.boolean().optional(),
  cookieDomain: z.string().regex(/^\.?([a-z0-9-]+\.)+[a-z]{2,63}$/).optional(),
})

const schema = z.object({
  GATEKIT_URL: z.string().url().optional(),
  GATEKIT_TIMEOUT_MS: z.coerce.number().int().min(100).max(30_000).default(2000),
  SITES_KUBE: z.enum(['in-cluster', 'kubeconfig', 'off']).default('off'),
  SITES_NAMESPACE: z.string().regex(/^[a-z0-9-]{1,63}$/).optional(),
  SITES_ZONES: z
    .string()
    .default('[{"suffix":"dev.stairling.com"}]')
    .transform((raw, ctx) => {
      try {
        return z.array(zoneSchema).parse(JSON.parse(raw)) as Zone[]
      } catch {
        ctx.addIssue({ code: 'custom', message: 'SITES_ZONES must be a JSON array of {suffix, wildcardTls?, cookieDomain?}' })
        return z.NEVER
      }
    }),
  SITES_COOKIE_DOMAIN: z.string().optional(),
  SITES_PLATFORM_NAMESPACES: z
    .string()
    .default('auth,kube-system,kube-public,kube-node-lease,cert-manager,ingress-nginx,envoy-gateway-system,monitoring')
    .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean)),
  SITES_RESERVED_HOSTS: z
    .string()
    .default('')
    .transform((v) => v.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)),
})

export type SitesConfig = z.infer<typeof schema> & { namespace: string }

let cached: SitesConfig | null = null

function podNamespace(): string | undefined {
  try {
    return readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'utf8').trim() || undefined
  } catch {
    return undefined
  }
}

export function sitesConfig(): SitesConfig {
  if (!cached) {
    const parsed = schema.parse(process.env)
    cached = { ...parsed, namespace: parsed.SITES_NAMESPACE ?? podNamespace() ?? 'auth' }
  }
  return cached
}

/** Test seam. */
export function resetSitesConfig(): void {
  cached = null
}
