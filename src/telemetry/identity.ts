/**
 * Who this process says it is, read from the variables the OpenTelemetry SDK itself reads.
 *
 * Named once, deliberately. If the log formatter carried its own copy of the service name, the copy
 * that went wrong would be the one nobody thinks to check — and a log line filed under a service
 * that does not exist in the traces cannot be joined to anything.
 *
 * Everything is optional. A deployment that sets none of these still logs; the correlation fields
 * are simply absent, which is honest, rather than filled with a guess.
 */

export type ServiceIdentity = {
  service: string | null
  env: string | null
  version: string | null
}

/** `key=value,key=value`, the W3C-ish form OTEL_RESOURCE_ATTRIBUTES uses. */
function attributes(raw: string | undefined): Map<string, string> {
  const found = new Map<string, string>()
  for (const pair of (raw ?? '').split(',')) {
    const at = pair.indexOf('=')
    if (at <= 0) continue
    const key = pair.slice(0, at).trim()
    const value = pair.slice(at + 1).trim()
    if (key && value) found.set(key, value)
  }
  return found
}

export function serviceIdentity(source: NodeJS.ProcessEnv = process.env): ServiceIdentity {
  const attrs = attributes(source.OTEL_RESOURCE_ATTRIBUTES)
  return {
    // OTEL_SERVICE_NAME wins over the attribute, which is the precedence the SDK applies.
    service: source.OTEL_SERVICE_NAME || attrs.get('service.name') || null,
    env: attrs.get('deployment.environment') || attrs.get('deployment.environment.name') || null,
    version: attrs.get('service.version') || null,
  }
}

/**
 * Whether a trace pipeline is asked for at all. One variable, and its absence is the OFF position:
 * an open-source deployment that wants nothing gets nothing, without a second flag to find.
 */
export function tracingRequested(source: NodeJS.ProcessEnv = process.env): boolean {
  return !!(source.OTEL_EXPORTER_OTLP_ENDPOINT || source.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT)
}
