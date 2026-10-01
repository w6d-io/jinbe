import { Counter, Gauge, Histogram } from 'prom-client'

/**
 * Prometheus series this service publishes (served by telemetry/metrics-server.ts).
 *
 * Label values are bounded: HTTP routes are patterns, OPAL entries are the datasource paths (one per
 * service at most), audit labels are catalog categories and results.
 */

export const httpRequestsCounter = new Counter({
  name: 'jinbe_http_requests_total',
  help: 'Total HTTP requests, by method/route/status_class',
  labelNames: ['method', 'route', 'status_class'] as const,
})

export const httpDurationHistogram = new Histogram({
  name: 'jinbe_http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route'] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
})

// ─── OPAL datasource ─────────────────────────────────────────────────────────
// Every entry OPAL fetches is a route under /api/admin/rbac. A 5xx there means OPA keeps stale data
// for that entry, which nothing else surfaces — hence the per-entry last-success timestamp.

export const opalDatasourceRequests = new Counter({
  name: 'jinbe_opal_datasource_requests_total',
  help: 'OPAL datasource fetches, by entry and status class',
  labelNames: ['entry', 'status_class'] as const,
})

export const opalDatasourceDuration = new Histogram({
  name: 'jinbe_opal_datasource_duration_seconds',
  help: 'OPAL datasource fetch latency in seconds, by entry',
  labelNames: ['entry'] as const,
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
})

export const opalDatasourceLastSuccess = new Gauge({
  name: 'jinbe_opal_datasource_last_success_timestamp_seconds',
  help: 'Unix time of the last 2xx answer per OPAL datasource entry',
  labelNames: ['entry'] as const,
})

// The push the other way: jinbe telling opal-server to have every client refetch the manifest.
// One count per burst of mutations, not per mutation (the push is debounced and retried).

export const opalPushes = new Counter({
  name: 'jinbe_opal_push_total',
  help: 'Datasource pushes to opal-server, by result (ok, failed after every retry)',
  labelNames: ['result'] as const,
})

export const opalPushLastSuccess = new Gauge({
  name: 'jinbe_opal_push_last_success_timestamp_seconds',
  help: 'Unix time of the last datasource push opal-server accepted',
})

// ─── Oathkeeper rules ────────────────────────────────────────────────────────

export const rulesGenerated = new Gauge({
  name: 'jinbe_rules_generated',
  help: 'Access rules in the last set served to Oathkeeper',
})

export const ruleCompileErrors = new Gauge({
  name: 'jinbe_rule_compile_errors',
  help: 'Rules in the last served set whose match URL does not compile under the regexp strategy',
})

// ─── Audit v1 ────────────────────────────────────────────────────────────────
// AU-15 compares this counter's hourly increase with the number of audit lines in Loki (the
// LOKI_AUDIT_SELECTOR stream: `log_type="audit"` as a label or as the parsed field).

export const auditV1Events = new Counter({
  name: 'jinbe_audit_v1_events_total',
  help: 'audit/v1 events written to the audit log line, by category and result',
  labelNames: ['category', 'result'] as const,
})

export const auditV1Failures = new Counter({
  name: 'jinbe_audit_v1_failures_total',
  help: 'audit/v1 events that a sink failed to take (log, outbox) or that failed validation (schema)',
  labelNames: ['sink'] as const,
})

// ─── Sign-in protection ──────────────────────────────────────────────────────
// One count per guarded Kratos submit (sign-in-protection/guard.ts). A flood shows up as refusals
// here before it shows up anywhere else; `fail_open` counts attempts let through unchecked.

export const signInGuardDecisions = new Counter({
  name: 'jinbe_sign_in_guard_decisions_total',
  help: 'Kratos flow submits judged by the sign-in guard, by flow and result',
  labelNames: ['flow', 'result'] as const,
})

// One count per self-service submit the gate saw (sign-in-protection/gate.ts): `step` is `send` for
// a submit that makes Kratos email a code or link, `other` for the rest (passed through unjudged).
export const signInGateDecisions = new Counter({
  name: 'jinbe_sign_in_gate_decisions_total',
  help: 'Kratos self-service submits judged by the sign-in gate before Kratos, by flow, step and result',
  labelNames: ['flow', 'step', 'result'] as const,
})

// ─── Shared read cache (src/cache) ───────────────────────────────────────────
// Label values are the cache namespaces, a fixed set declared in code.

export const cacheRequests = new Counter({
  name: 'jinbe_cache_requests_total',
  help: 'Cache reads, by namespace and result (hit, stale, miss, bypass)',
  labelNames: ['namespace', 'result'] as const,
})

export const cacheRefreshes = new Counter({
  name: 'jinbe_cache_refresh_total',
  help: 'Cache refreshes, by namespace and outcome (ok, error, skipped)',
  labelNames: ['namespace', 'outcome'] as const,
})

export const cacheRefreshDuration = new Histogram({
  name: 'jinbe_cache_refresh_duration_seconds',
  help: 'Time spent computing a cache entry from its upstream',
  labelNames: ['namespace'] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 15],
})

export const cacheInvalidations = new Counter({
  name: 'jinbe_cache_invalidations_total',
  help: 'Cache invalidations, by namespace and scope (all, key)',
  labelNames: ['namespace', 'scope'] as const,
})

// ─── Entity notifications (services/notifications) ───────────────────────────
// A failed attempt is retried with backoff; after the last one the event goes to the dead-letter
// stream (`notifications:dead`), which the Home attention queue counts.

export const notificationAttemptFailures = new Counter({
  name: 'jinbe_notifications_attempt_failures_total',
  help: 'Notification delivery attempts that failed, by notifier',
  labelNames: ['notifier'] as const,
})

export const notificationsDeadLettered = new Counter({
  name: 'jinbe_notifications_dead_lettered_total',
  help: 'Notifications moved to the dead-letter stream, by why (attempts_exhausted, rejected, expired, unreadable)',
  labelNames: ['reason'] as const,
})

// authz v2: a code-owned rbac2 key found changed by hand and rewritten (authz-v2/store.ts converge).
export const rbacOwnedDrift = new Counter({
  name: 'jinbe_rbac_owned_drift_total',
  help: 'Code-owned authz v2 keys found edited outside jinbe and converged back, by key',
  labelNames: ['key'] as const,
})
