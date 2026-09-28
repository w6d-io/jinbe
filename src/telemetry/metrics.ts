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
