import { z } from 'zod'

/**
 * The Home contract (home-data.md §3.4–3.5, settled in §11): one envelope per module, each module
 * loading, failing and ageing on its own. These schemas are the source of truth for the response and
 * for the OpenAPI document; the TypeScript types are inferred from them.
 *
 * Privacy (§6): no field carries an email. People are `{id, label}` with a display name, else
 * "Unknown user"; aggregates key on route patterns, site names, catalog events, org ids and actor ids.
 */

export const HOME_MODULES = ['health', 'attention', 'people', 'activity', 'access', 'sites', 'changes', 'actions', 'me'] as const
export type HomeModuleName = (typeof HOME_MODULES)[number]

export const homeWindowSchema = z.enum(['24h', '7d'])
export type HomeWindow = z.infer<typeof homeWindowSchema>

export const homeQuerySchema = z.object({
  window: homeWindowSchema.default('24h'),
  org: z.string().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/).optional(),
}).strict()

export const moduleStatusSchema = z.enum(['ok', 'unavailable', 'forbidden'])
export const moduleReasonSchema = z.enum(['warming', 'timeout', 'source_down', 'not_configured', 'not_deployed'])
export const sourceStateSchema = z.enum(['ok', 'down', 'timeout', 'warming', 'not_configured', 'not_deployed'])
export const connectSchema = z.object({ setting: z.string(), docs: z.string() })
export const sourceDetailSchema = z.object({ state: sourceStateSchema, connect: connectSchema.optional() })

export type ModuleReason = z.infer<typeof moduleReasonSchema>
export type SourceState = z.infer<typeof sourceStateSchema>
export type Connect = z.infer<typeof connectSchema>
export type SourceDetail = z.infer<typeof sourceDetailSchema>

// ─── health ──────────────────────────────────────────────────────────────────

export const componentIdSchema = z.enum([
  'gateway', 'gateway_rules', 'opa', 'opal_data', 'kratos', 'jinbe', 'redis', 'audit_store', 'audit_archive', 'certificates',
])
export const componentStateSchema = z.enum(['ok', 'degraded', 'down', 'unknown', 'not_deployed'])
export const pageLinkSchema = z.object({ page: z.string(), params: z.record(z.string()).optional(), anchor: z.string().optional() })
export const linkSchema = z.union([pageLinkSchema, z.object({ grafana: z.string() })])

export const healthSchema = z.object({
  environment: z.object({ name: z.string(), production: z.boolean() }),
  /** In request order: gateway → gateway rules → policy engine → policy sync → sign-in → console API → data store → audit → certificates. */
  components: z.array(z.object({
    id: componentIdSchema,
    state: componentStateSchema,
    /** Short, no PII: "2/2 engines on d592a186", "rollout settled", "3 certs, soonest 77 d". */
    summary: z.string(),
    since: z.string().optional(),
    link: linkSchema.optional(),
  })),
})
export type Health = z.infer<typeof healthSchema>
export type HealthComponent = Health['components'][number]
export type ComponentState = z.infer<typeof componentStateSchema>

// ─── attention ───────────────────────────────────────────────────────────────

export const attentionKindSchema = z.enum([
  'site_request_pending', 'site_unapplied', 'site_draft_stale', 'site_condition', 'site_drift',
  'gateway_rollout', 'engines_out_of_sync', 'opal_data_stale', 'rule_compile_errors', 'cert_expiring',
  'privileged_no_mfa', 'privileged_self_granted', 'privileged_dormant',
  'recert_overdue', 'recert_inbox', 'audit_archive_lag', 'audit_emit_failures',
  'migration_regressions', 'login_failure_spike', 'deny_spike', 'unassigned_users',
  // HOME-later (§11): emitted once J12 / the audit/v1 stream exist.
  'site_members_no_mfa', 'apikey_unused',
])
export const severitySchema = z.enum(['critical', 'warning', 'info'])

export const attentionItemSchema = z.object({
  /** Stable `${kind}:${ref}`. */
  id: z.string(),
  kind: attentionKindSchema,
  severity: severitySchema,
  title: z.string(),
  detail: z.string().optional(),
  subject: z.object({
    type: z.enum(['site', 'user', 'campaign', 'request', 'org', 'component']),
    id: z.string(),
    /** A display name, never an email. */
    label: z.string(),
  }).optional(),
  /** When the condition started (ISO). */
  since: z.string(),
  /** The caller's rights let them act on it (approvals: `sites:apply`). */
  actionable: z.boolean(),
  target: z.object({ page: z.string(), params: z.record(z.string()), anchor: z.string().optional() }),
  /** Count-type and spike items: `{count}`, `{factor, current, baseline}`. */
  metrics: z.record(z.number()).optional(),
})
export const attentionSchema = z.object({
  /** Severity desc, then oldest first; at most 50. */
  items: z.array(attentionItemSchema),
  counts: z.object({ critical: z.number(), warning: z.number(), info: z.number() }),
  truncated: z.boolean(),
})
export type Attention = z.infer<typeof attentionSchema>
export type AttentionItem = z.infer<typeof attentionItemSchema>
export type AttentionKind = z.infer<typeof attentionKindSchema>
export type Severity = z.infer<typeof severitySchema>

// ─── people ──────────────────────────────────────────────────────────────────

export const peopleSchema = z.object({
  identities: z.number(),
  active: z.number(),
  inactive: z.number(),
  /** Platform only. */
  fullAccess: z.number().optional(),
  unassigned: z.number().optional(),
  mfa: z.object({ enrolled: z.number(), of: z.number(), asOf: z.string() }).optional(),
  /** HOME-later (J6): platform + support. */
  sessionsActive: z.object({ count: z.number(), asOf: z.string() }).optional(),
  byGroup: z.array(z.object({ group: z.string(), members: z.number() })).optional(),
  /** Platform: top 20 by members. Org admin: its orgs. */
  byOrg: z.array(z.object({ orgId: z.string(), name: z.string(), members: z.number() })).optional(),
  orgsTotal: z.number().optional(),
})
export type People = z.infer<typeof peopleSchema>

// ─── activity ────────────────────────────────────────────────────────────────

export const activitySchema = z.object({
  window: homeWindowSchema,
  signIns: z.object({
    succeeded: z.number(),
    failed: z.number(),
    prevSucceeded: z.number(),
    prevFailed: z.number(),
    distinctUsers: z.number(),
    /** ≥ 3 × the 7-day median for this hour with ≥ 20 failures, rounded to one decimal; else null. */
    failedFactor: z.number().nullable(),
    /** The same spike with its inputs (failures in the last hour, the 7-day same-hour median); null below the floor. */
    failedSpike: z.object({ factor: z.number(), current: z.number(), baseline: z.number() }).nullable(),
  }),
  /** 24 buckets. */
  series: z.array(z.object({ t: z.string(), succeeded: z.number(), failed: z.number(), changes: z.number() })),
  byCategory: z.record(z.number()),
  denied: z.object({ total: z.number(), prev: z.number() }),
  /** Console API guard denials, keyed on the ROUTE PATTERN (never a raw path). */
  topDeniedRoutes: z.array(z.object({ route: z.string(), count: z.number() })),
  /** Platform readers only; label = display name. */
  topActors: z.array(z.object({ actorId: z.string(), label: z.string(), count: z.number() })).optional(),
  source: z.enum(['loki', 'redis-legacy']),
  truncated: z.boolean(),
})
export type Activity = z.infer<typeof activitySchema>

// ─── access (gateway decisions; not deployed until OBS-1.4) ─────────────────

export const accessSchema = z.object({
  window: homeWindowSchema,
  totals: z.object({ allow: z.number(), deny: z.number(), notFound: z.number() }),
  bySite: z.array(z.object({ site: z.string(), allow: z.number(), deny: z.number(), denyRate: z.number() })),
  topDeniedRoutes: z.array(z.object({ site: z.string(), route: z.string(), method: z.string(), count: z.number() })),
  series: z.array(z.object({ t: z.string(), allow: z.number(), deny: z.number() })),
  source: z.enum(['decision-log', 'oathkeeper-log']),
})
export type AccessDecisions = z.infer<typeof accessSchema>

// ─── sites ───────────────────────────────────────────────────────────────────

const personSchema = z.object({ id: z.string().nullable(), label: z.string() })

export const sitesSummarySchema = z.object({
  counts: z.object({ live: z.number(), attention: z.number(), draft: z.number(), paused: z.number(), deleted: z.number() }),
  pendingRequests: z.number(),
  /** Site CRs whose Ready is not True; null when the cluster is not readable (SITES_KUBE off). */
  unhealthy: z.number().nullable(),
  /** Top 12: attention first, then most recently applied. */
  list: z.array(z.object({
    name: z.string(),
    displayName: z.string(),
    host: z.string().nullable(),
    status: z.enum(['live', 'attention', 'draft', 'paused']),
    ready: z.boolean().nullable(),
    version: z.number(),
    appliedVersion: z.number().nullable(),
    appliedAt: z.string().nullable(),
    appliedBy: personSchema.nullable(),
    draftAt: z.string().nullable(),
    orgs: z.number(),
  })),
  migration: z.object({ phase: z.string(), regressions: z.number(), rollbackUntil: z.string().nullable() }).optional(),
})
export type SitesSummary = z.infer<typeof sitesSummarySchema>

// ─── changes ─────────────────────────────────────────────────────────────────

export const changesSchema = z.object({
  items: z.array(z.object({
    eventId: z.string(),
    ts: z.string(),
    /** Catalog key, e.g. `site.applied` (legacy stream: `<category>.<verb>`). */
    event: z.string(),
    category: z.string(),
    result: z.string(),
    actor: personSchema.extend({ type: z.enum(['user', 'service', 'system', 'anonymous']) }),
    target: z.object({ type: z.string(), id: z.string().nullable(), label: z.string() }).optional(),
    site: z.string().optional(),
    orgId: z.string().optional(),
    link: z.object({ page: z.literal('audit'), params: z.object({ eventId: z.string(), ts: z.string() }) }),
  })),
  source: z.enum(['loki', 'redis-legacy']),
})
export type Changes = z.infer<typeof changesSchema>

// ─── actions ─────────────────────────────────────────────────────────────────

export const quickActionIdSchema = z.enum([
  'find_user', 'invite_user', 'revoke_sessions', 'send_recovery',
  'new_site', 'review_requests', 'open_gateway',
  'grant_access', 'org_api_key', 'start_recert', 'open_audit', 'check_access',
])
export const quickActionsSchema = z.object({
  items: z.array(z.object({
    id: quickActionIdSchema,
    enabled: z.boolean(),
    reason: z.enum(['no_permission', 'mfa_required', 'not_deployed', 'nothing_to_do']).optional(),
    /** `review_requests`: pending requests the caller may decide. */
    count: z.number().optional(),
  })),
})
export type QuickActions = z.infer<typeof quickActionsSchema>
export type QuickActionId = z.infer<typeof quickActionIdSchema>

// ─── me ──────────────────────────────────────────────────────────────────────

export const meSchema = z.object({
  subject: z.string(),
  name: z.string().nullable(),
  roles: z.array(z.string()),
  /** The organisations the caller administers (names from the organisation store). */
  orgs: z.array(z.object({ id: z.string(), name: z.string() })),
  recertPending: z.number(),
  aal: z.enum(['aal1', 'aal2']),
})
export type Me = z.infer<typeof meSchema>

// ─── envelope ────────────────────────────────────────────────────────────────

export const MODULE_DATA = {
  health: healthSchema,
  attention: attentionSchema,
  people: peopleSchema,
  activity: activitySchema,
  access: accessSchema,
  sites: sitesSummarySchema,
  changes: changesSchema,
  actions: quickActionsSchema,
  me: meSchema,
} as const satisfies Record<HomeModuleName, z.ZodTypeAny>

export interface ModuleDataMap {
  health: Health
  attention: Attention
  people: People
  activity: Activity
  access: AccessDecisions
  sites: SitesSummary
  changes: Changes
  actions: QuickActions
  me: Me
}

function envelopeOf<T extends z.ZodTypeAny>(data: T) {
  return z.object({
    status: moduleStatusSchema,
    /** Present whenever status is `unavailable`. */
    reason: moduleReasonSchema.optional(),
    /** When the data was computed (ISO); null when never. */
    asOf: z.string().nullable(),
    /** Served past its fresh window (source slow or down): the last good value. */
    stale: z.boolean(),
    /** Per-source detail; a missing source carries its own `connect`. */
    sources: z.record(sourceDetailSchema),
    /** Present when reason is `not_configured` / `not_deployed`. */
    connect: connectSchema.optional(),
    /** Present when status is `ok`. */
    data: data.optional(),
  })
}

export const moduleEnvelopeSchema = envelopeOf(z.unknown())
export type ModuleEnvelope<T = unknown> = Omit<z.infer<typeof moduleEnvelopeSchema>, 'data'> & { data?: T }

export const homeResponseSchema = z.object({
  scope: z.object({
    platform: z.boolean(),
    /** Org ids only; names come from GET /api/me/organizations. */
    orgs: z.array(z.string()),
    roles: z.array(z.string()),
    /** The `org` this answer is narrowed to, else null. */
    org: z.string().nullable(),
  }),
  generatedAt: z.string(),
  window: homeWindowSchema,
  /** Only the modules this caller may see; the others are omitted. */
  modules: z.object({
    health: envelopeOf(healthSchema).optional(),
    attention: envelopeOf(attentionSchema).optional(),
    people: envelopeOf(peopleSchema).optional(),
    activity: envelopeOf(activitySchema).optional(),
    access: envelopeOf(accessSchema).optional(),
    sites: envelopeOf(sitesSummarySchema).optional(),
    changes: envelopeOf(changesSchema).optional(),
    actions: envelopeOf(quickActionsSchema).optional(),
    me: envelopeOf(meSchema).optional(),
  }),
})
export type HomeResponse = z.infer<typeof homeResponseSchema>
