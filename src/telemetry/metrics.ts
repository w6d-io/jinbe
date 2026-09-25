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
// AU-15 compares this counter's hourly increase with the number of {log_type="audit"} lines in Loki.

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
