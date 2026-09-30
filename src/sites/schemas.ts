import { z } from 'zod'
import { sitesConfig } from './config.js'

/**
 * The Site intent (site-ux.md §14.1) and the request bodies of /api/admin/sites.
 *
 * Validated here, at the boundary, so render and the store only ever see a well-formed intent.
 * Format only — what the gateway would make of a pattern is gatekit's question, not ours.
 */

export const SYSTEM_SITES = ['jinbe', 'kuma', 'global'] as const

export const HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const

const name = z.string().regex(/^[a-z][a-z0-9-]{1,39}$/, 'lowercase letters, digits and dashes, 2-40 characters')
const id = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/, 'lowercase letters, digits and dashes')
// Gate ids become Site CR gate names (≤ 32 chars, `<id>-preflight` included).
const gateId = z.string().regex(/^[a-z]([a-z0-9-]{0,20}[a-z0-9])?$/, 'lowercase letters, digits and dashes, at most 22 characters')
const host = z
  .string()
  .max(253)
  .transform((h) => h.toLowerCase())
  .pipe(z.string().regex(/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/, 'a DNS host name'))
// A public request path: literal segments, `:param` segments and a trailing `:any*`.
const routePath = z
  .string()
  .max(512)
  .regex(/^\/([A-Za-z0-9._~@-]+|:[A-Za-z_][A-Za-z0-9_]*|:any\*)?(\/([A-Za-z0-9._~@-]+|:[A-Za-z_][A-Za-z0-9_]*|:any\*))*$/, 'a path like /api/:id or /assets/:any*')
  .refine((p) => !p.slice(0, -5).includes(':any*'), ':any* may only end a path')
const permission = z.string().regex(/^[a-z][a-z0-9_.-]*:[a-z*][a-z0-9_*-]*$/, 'a permission like resource:verb')
const method = z.enum(HTTP_METHODS)
const dnsLabel = z.string().regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/, 'a DNS label')

export const handlerSchema = z
  .object({ handler: z.string().regex(/^[a-z][a-z0-9_]{1,40}$/), config: z.record(z.unknown()).optional() })
  .strict()

export const accessSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('public') }).strict(),
  z.object({ kind: z.literal('signed-in') }).strict(),
  z.object({ kind: z.literal('permission'), permission }).strict(),
  z.object({ kind: z.literal('deny') }).strict(),
])

export const gateSchema = z
  .object({
    id: gateId,
    label: z.string().min(1).max(80),
    authenticators: z.array(handlerSchema).min(1).max(8),
    authorizer: z.union([z.literal('policy'), handlerSchema]),
    mutators: z.array(handlerSchema).min(1).max(8),
    errors: z.union([z.enum(['platform', 'website', 'api']), z.array(handlerSchema).min(1).max(8)]),
    methods: z.array(method).min(1).optional(),
    preflight: z.boolean().optional(),
    // Expert: a raw Oathkeeper match URL for this gate, compile- and overlap-checked by gatekit.
    // Other raw rule overrides (site-ux §6.5) are not accepted yet.
    expert: z.object({ matchUrl: z.string().min(1).max(2048).optional() }).strict().optional(),
  })
  .strict()

export const routeSchema = z
  .object({
    id,
    methods: z.array(method).min(1),
    path: routePath,
    gate: id,
    access: accessSchema,
    orgParam: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/).optional(),
    source: z.enum(['manual', 'openapi', 'template']).default('manual'),
    pinned: z.boolean().optional(),
    // An imported route's operation (operationId, else `METHOD path`): the key a re-import matches on.
    op: z.string().min(1).max(600).optional(),
  })
  .strict()

/** The last OpenAPI import into this site (openapi-import.md §3): what the next re-import is compared with. */
export const openapiImportSchema = z
  .object({
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    title: z.string().max(200),
    version: z.string().max(64),
    source: z.literal('upload'),
    importedAt: z.string().datetime(),
    importedBy: z.string().max(254),
  })
  .strict()

/** Hard ceiling of SITES_MAX_ROUTES; the configured value is checked at parse time. */
export const ROUTES_HARD_MAX = 2000
const maxRoutes = (items: unknown[], ctx: z.RefinementCtx) => {
  const max = sitesConfig().SITES_MAX_ROUTES
  if (items.length > max) ctx.addIssue({ code: 'too_big', type: 'array', maximum: max, inclusive: true, message: `at most ${max} routes (SITES_MAX_ROUTES)` })
}

const rolesMap = z.record(z.string().regex(/^[a-z][a-z0-9_-]{0,39}$/), z.array(z.union([permission, z.literal('*')])))

export const siteSchema = z
  .object({
    name,
    displayName: z.string().min(1).max(80),
    description: z.string().max(500).optional(),
    icon: z.string().max(64).optional(),
    address: z
      .object({ host, pathPrefix: routePath.refine((p) => !p.includes(':') && p !== '/', 'a literal prefix like /payroll').optional() })
      .strict(),
    // An in-cluster Service, never a free URL: the operator renders the URL, and admission pins it
    // to `<svc>.<ns>.svc.cluster.local` outside the platform namespaces (site-operator.md §5).
    upstream: z
      .object({
        // Same patterns as the Site CRD (site-operator config/crd/bases/auth.w6d.io_sites.yaml).
        service: z.string().regex(/^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/, 'a Service name'),
        namespace: dnsLabel,
        port: z.number().int().min(1).max(65535),
        scheme: z.enum(['http', 'https']).optional(),
        preserveHost: z.boolean().optional(),
        stripPath: z.string().max(256).regex(/^\/[^\s]*$/, 'an absolute path').optional(),
      })
      .strict(),
    // zone (default): rules only, the zone's wildcard already reaches the gateway. vanity: one Ingress.
    exposure: z.object({ mode: z.enum(['zone', 'vanity']) }).strict().default({ mode: 'zone' }),
    gates: z.array(gateSchema).min(1).max(20),
    routes: z
      .object({
        items: z
          .array(routeSchema)
          .max(ROUTES_HARD_MAX)
          .superRefine(maxRoutes),
        catchAll: z.object({ gate: id, access: accessSchema }).strict(),
        openapi: openapiImportSchema.optional(),
      })
      .strict(),
    roles: z.union([z.enum(['standard', 'readonly', 'operator']), rolesMap]),
    groups: z
      .object({
        platform: z.record(z.string().min(1).max(64), z.array(z.string())),
        orgGrantable: z.record(z.string().min(1).max(64), z.object({ label: z.string().min(1).max(80), roles: z.array(z.string()).min(1) }).strict()),
      })
      .strict(),
    orgs: z.array(z.string().uuid()).max(500),
    // Per-site login (S-4): 2FA is published to OPA as data.site_login[<site>] (routes = route ids,
    // honoured under every scope); branding is served by the public by-host lookup.
    login: z
      .object({
        twoFactor: z.object({ scope: z.enum(['none', 'writes', 'all', 'routes']), routes: z.array(id).max(ROUTES_HARD_MAX).superRefine(maxRoutes).optional(), clients: z.enum(['exempt', 'refused']) }).strict(),
        reach: z.enum(['granted', 'any-account']),
        branding: z
          .object({
            name: z.string().min(1).max(80).optional(),
            // The logo itself is uploaded through PUT /sites/:name/logo; this field is kept for the editor.
            logo: z.string().max(64).optional(),
            accent: z.string().regex(/^#[0-9a-fA-F]{6}$/, 'a colour like #1A2B3C').optional(),
            welcome: z.string().max(280).refine((w) => !/[<>]/.test(w), 'plain text only').optional(),
            helpUrl: z.string().url().max(2048).refine((u) => u.startsWith('https://'), 'an https:// link').optional(),
          })
          .strict()
          .optional(),
        postLogoutUrl: z.string().url().optional(),
        // Where a visitor lands after signing in to this site, instead of Kratos' default return URL.
        // On the site's own host (render checks it); served by the public by-host lookup and /mine.
        defaultReturnUrl: z.string().url().max(2048).refine((u) => u.startsWith('https://'), 'an https:// link').optional(),
      })
      .strict()
      .optional(),
    state: z.enum(['active', 'paused']).default('active'),
  })
  .strict()

export type Site = z.infer<typeof siteSchema>
export type Gate = z.infer<typeof gateSchema>
export type Route = z.infer<typeof routeSchema>
export type Access = z.infer<typeof accessSchema>
export type Handler = z.infer<typeof handlerSchema>

// ── request bodies ───────────────────────────────────────────

export const nameParamsSchema = z.object({ name })
export const draftBodySchema = z.object({ site: z.unknown(), baseVersion: z.number().int().min(0).optional() }).strict()
export const previewBodySchema = z.object({ site: siteSchema, baseVersion: z.number().int().min(0).optional() }).strict()
export const diffBodySchema = z.object({ site: siteSchema.optional() }).strict()
/**
 * An ephemeral site's time to live (wave 19): seconds, or `<n>m|h|d`; 1 hour to 7 days, 24 hours when
 * left out. When it passes, the site is paused (never deleted).
 */
export const EPHEMERAL_TTL = { minSec: 3600, maxSec: 7 * 24 * 3600, defaultSec: 24 * 3600 } as const
const UNIT_SEC = { m: 60, h: 3600, d: 86_400 } as const
export const ttlSchema = z
  .union([z.number().int(), z.string().regex(/^\d{1,5}[mhd]$/, 'seconds, or a duration like 30m, 12h, 3d')])
  .transform((v) => (typeof v === 'number' ? v : Number(v.slice(0, -1)) * UNIT_SEC[v.slice(-1) as keyof typeof UNIT_SEC]))
  .refine((sec) => sec >= EPHEMERAL_TTL.minSec && sec <= EPHEMERAL_TTL.maxSec, 'between 1 hour and 7 days')
export const ephemeralSchema = z.object({ ttl: ttlSchema.optional() }).strict()
/** `ephemeral`: make the site expire (or move its expiry); null makes it permanent; absent leaves it as it is. */
export const saveBodySchema = z.object({ site: siteSchema, note: z.string().max(280).optional(), ephemeral: ephemeralSchema.nullable().optional() }).strict()
export const renewTtlBodySchema = z.object({ ttl: ttlSchema.optional() }).strict()
export const deletionRequestBodySchema = z.object({ reason: z.string().max(280).optional() }).strict()
/** Codes of the security findings (findings.ts) a person confirms by publishing: `confirm` findings only. */
export const acknowledgeSchema = z.array(z.string().regex(/^[a-z][a-z0-9_]{0,63}$/, 'a finding code')).max(32)
export const applyBodySchema = z.object({ version: z.number().int().min(1), acknowledge: acknowledgeSchema.optional() }).strict()
export const rollbackBodySchema = z.object({ toVersion: z.number().int().min(1), note: z.string().max(280).optional() }).strict()
export const checkHostBodySchema = z.object({ host, pathPrefix: z.string().max(512).optional(), site: name.optional() }).strict()
export const matchBodySchema = z
  .object({
    method,
    url: z.string().url().max(2048),
    against: z.enum(['draft', 'live']).default('live'),
    site: siteSchema.optional(),
  })
  .strict()
export const renderTemplateBodySchema = z
  .object({
    template: z.string().min(1).max(8192),
    kind: z.enum(['header', 'cookie', 'payload', 'claims']),
    name: z.string().max(128).optional(),
    sample: z
      .object({
        subject: z.string().max(128).optional(),
        email: z.string().email().optional(),
        aal: z.enum(['aal1', 'aal2']).optional(),
        anonymous: z.boolean().optional(),
        method,
        url: z.string().url().max(2048),
        pattern: z.string().max(4096).optional(),
      })
      .strict(),
  })
  .strict()

// ── zones (zones.auth.w6d.io) ────────────────────────────────

// The Zone CRD's own domain pattern (site-operator api/v1alpha1 ZoneSpec.Domain).
const zoneDomain = z
  .string()
  .max(253)
  .transform((d) => d.toLowerCase().replace(/^\*\./, '').replace(/\.$/, ''))
  .pipe(z.string().regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/, 'a domain like apps.stairfleet.com'))
// Zone names are cluster object names, at most 50 characters (Zone CRD rule).
const zoneName = z.string().regex(/^[a-z0-9]([a-z0-9-]{0,48}[a-z0-9])?$/, 'lowercase letters, digits and dashes, at most 50 characters')
const k8sName = z.string().regex(/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/, 'a Kubernetes object name')

export const zoneParamsSchema = z.object({ name: zoneName })
const zoneTls = z
  .object({ mode: z.enum(['default', 'issuer', 'secret']), issuer: k8sName.optional(), secretName: k8sName.optional() })
  .strict()
  .superRefine((t, ctx) => {
    if (t.mode === 'secret' && !t.secretName) ctx.addIssue({ code: 'custom', path: ['secretName'], message: 'mode secret needs secretName' })
    if (t.mode !== 'secret' && t.secretName) ctx.addIssue({ code: 'custom', path: ['secretName'], message: 'secretName is only for mode secret' })
    if (t.mode !== 'issuer' && t.issuer) ctx.addIssue({ code: 'custom', path: ['issuer'], message: 'issuer is only for mode issuer' })
  })
// The Zone CRD's gateway (site-operator ZoneGateway): a Gateway API Gateway, optionally one listener.
const zoneGateway = z
  .object({
    namespace: z.string().regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/, 'a namespace'),
    name: k8sName,
    sectionName: z.string().regex(/^[a-z0-9]([a-z0-9-]{0,251}[a-z0-9])?$/, 'a listener name').optional(),
  })
  .strict()
const zoneIngress = z.enum(['wildcard', 'per-site', 'none'])

export const createZoneBodySchema = z
  .object({
    domain: zoneDomain,
    name: zoneName.optional(),
    ingress: zoneIngress.optional(),
    tls: zoneTls.default({ mode: 'default' }),
    ingressClass: k8sName.optional(),
    gateway: zoneGateway.optional(),
    /** Create on the nginx Ingress although a WAF-protected Gateway exists (explicit, audited). */
    acknowledgeNoWaf: z.boolean().optional(),
  })
  .strict()
  .superRefine((b, ctx) => {
    if (b.ingress === 'none' && !b.gateway) ctx.addIssue({ code: 'custom', path: ['ingress'], message: 'ingress none needs a gateway: a zone needs an entry point' })
  })
/**
 * A zone's exposure, changed in place (the domain never changes): the ingress mode, the gateway
 * (null detaches it), TLS. `confirm` acknowledges the DNS check of a move to `ingress: none`.
 */
export const updateZoneBodySchema = z
  .object({
    ingress: zoneIngress.optional(),
    gateway: zoneGateway.nullable().optional(),
    tls: zoneTls.optional(),
    ingressClass: k8sName.nullable().optional(),
    confirm: z.boolean().optional(),
    /** Detach the Gateway although a WAF-protected one exists (explicit, audited). */
    acknowledgeNoWaf: z.boolean().optional(),
  })
  .strict()
  .refine((b) => b.ingress !== undefined || b.gateway !== undefined || b.tls !== undefined || b.ingressClass !== undefined, 'nothing to change')
export const suggestZoneBodySchema = z.object({ host }).strict()
export type CreateZoneBody = z.infer<typeof createZoneBodySchema>
export type UpdateZoneBody = z.infer<typeof updateZoneBodySchema>
