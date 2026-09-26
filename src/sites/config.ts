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
 *   SITES_UPSTREAM_ALLOW       exact `namespace/service` exceptions to it (e.g. auth-dev/echo).
 *   SITES_RESERVED_HOSTS   comma-separated platform hosts no site may take (kuma, login, auth…).
 *   SITES_RULES_LOADED_TIMEOUT_MS  how long an apply waits for RulesLoaded before rolling back (120 s).
 *   SITES_APPLY_POLL_MS    how often an apply/cut-over watches the Site CRs (1000; 0 = no watcher).
 *   SITES_FOUR_EYES        off | high-risk | all (default off): which applies need a second super_admin.
 *   SITES_SYNC_INTERVAL_MS re-create missing/drifted Site CRs from the intent every … (60 s; 0 = off).
 *   SITES_SYNC_MAX_PER_TICK  at most this many Site CRs rewritten per sync tick (3).
 *   SITES_ACCESS_URL       login-ui /access page; browser gates of 2FA sites redirect `forbidden` there.
 *   SITES_PUBLIC_RATE_LIMIT  requests per minute per IP on the public site endpoints (60).
 *   SITES_MIGRATION_DUALRUN_MIN_SEC   dual-run length before cut-over is allowed (3600).
 *   SITES_MIGRATION_ROLLBACK_DAYS     how long after cut-over a rollback is offered (7).
 *   SITES_ENV              environment name shown in kuma (default: NODE_ENV).
 *   SITES_PRODUCTION       true on a production environment (stricter guards in kuma; default false).
 *   SITES_RULES_LOAD_EXPECTED_SEC  typical save→enforced time shown on the timeline (10; ~90 with maester in controller mode).
 *   SITES_ZONE_ALLOWED_PARENTS  comma-separated domains a Zone may be created at or under (e.g.
 *                          dev.stairling.com,stairfleet.com). Empty = no Zone can be created from kuma.
 *   SITES_ZONE_ISSUERS     comma-separated ClusterIssuers offered for TLS mode `issuer` (mirror the
 *                          operator's allowed issuers). A named issuer must be one of them;
 *                          mode `issuer` without a name uses the operator's default issuer.
 *   SITES_INGRESS_ADDRESSES  comma-separated IPs/hostnames of the platform ingress load balancer, which a
 *                          new zone's wildcard DNS must point at. Empty = learnt from the existing Zones.
 *   SITES_ZONE_DNS_TIMEOUT_MS  per DNS lookup of the wildcard probe (1500).
 */

const zoneSchema = z.object({
  suffix: z.string().regex(/^([a-z0-9-]+\.)+[a-z]{2,63}$/),
  wildcardTls: z.boolean().optional(),
  cookieDomain: z.string().regex(/^\.?([a-z0-9-]+\.)+[a-z]{2,63}$/).optional(),
})

const list = (v: string) => v.split(',').map((s) => s.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean)

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
  // Exact `namespace/service` pairs allowed as upstreams despite SITES_PLATFORM_NAMESPACES. Platform data
  // services (kratos-admin, OPA, OPAL, Redis, Postgres) stay refused whatever this says.
  SITES_UPSTREAM_ALLOW: z
    .string()
    .default('')
    .transform((v) => v.split(',').map((s) => s.trim()).filter((s) => /^[a-z0-9-]+\/[a-z0-9-]+$/.test(s))),
  SITES_RESERVED_HOSTS: z
    .string()
    .default('')
    .transform((v) => v.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)),
  SITES_RULES_LOADED_TIMEOUT_MS: z.coerce.number().int().min(1000).max(3_600_000).default(120_000),
  SITES_APPLY_POLL_MS: z.coerce.number().int().min(0).max(60_000).default(1000),
  SITES_FOUR_EYES: z.enum(['off', 'high-risk', 'all']).default('off'),
  SITES_SYNC_INTERVAL_MS: z.coerce.number().int().min(0).max(86_400_000).default(60_000),
  SITES_SYNC_MAX_PER_TICK: z.coerce.number().int().min(1).max(100).default(3),
  SITES_ACCESS_URL: z.string().url().optional(),
  SITES_PUBLIC_RATE_LIMIT: z.coerce.number().int().min(1).max(10_000).default(60),
  SITES_MIGRATION_DUALRUN_MIN_SEC: z.coerce.number().int().min(0).max(30 * 86_400).default(3600),
  SITES_MIGRATION_ROLLBACK_DAYS: z.coerce.number().int().min(1).max(90).default(7),
  SITES_ENV: z.string().max(64).optional(),
  SITES_PRODUCTION: z.enum(['true', 'false']).default('false').transform((v) => v === 'true'),
  SITES_RULES_LOAD_EXPECTED_SEC: z.coerce.number().int().min(1).max(3600).default(10),
  SITES_ZONE_ALLOWED_PARENTS: z.string().default('').transform(list).pipe(z.array(z.string().regex(/^([a-z0-9-]+\.)+[a-z]{2,63}$/, 'a domain'))),
  SITES_ZONE_ISSUERS: z.string().default('').transform(list).pipe(z.array(z.string().regex(/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/, 'a ClusterIssuer name'))),
  SITES_INGRESS_ADDRESSES: z.string().default('').transform(list),
  SITES_ZONE_DNS_TIMEOUT_MS: z.coerce.number().int().min(100).max(10_000).default(1500),
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
