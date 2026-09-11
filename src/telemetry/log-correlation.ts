import { trace, isSpanContextValid } from '@opentelemetry/api'
import { serviceIdentity } from './identity.js'

/**
 * The fields that let a log line and its trace find each other.
 *
 * FLAT, and named `trace_id` / `span_id` exactly. Grafana joins a Loki line to a Tempo trace with a
 * derived field whose regex reads `"trace_id":"(\w+)"` from the raw line — a nested identifier, or
 * one under another name, is one nothing can join on. This is a contract with the datasource, not a
 * style choice.
 *
 * Omitted rather than zeroed when there is no span: `00000000000000000000000000000000` looks like
 * an identifier and matches the regex, so it would produce a link to a trace that never existed.
 *
 * Works with the SDK off. `trace.getActiveSpan()` returns nothing when no provider is registered,
 * so this costs one call and adds no field — logging never depends on telemetry being on.
 */
export function traceFields(): Record<string, string> {
  const context = trace.getActiveSpan()?.spanContext()
  if (!context || !isSpanContextValid(context)) return {}
  return { trace_id: context.traceId, span_id: context.spanId }
}

/**
 * The identity every line carries, resolved once at startup. A field with nothing to say is left
 * out entirely — an empty `version` is a worse answer than no `version`.
 */
export function logBase(): Record<string, string> {
  const { service, env, version } = serviceIdentity()
  return {
    ...(service ? { service } : {}),
    ...(env ? { env } : {}),
    ...(version ? { version } : {}),
  }
}
