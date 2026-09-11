/**
 * The trace pipeline, started before anything it instruments.
 *
 * PRELOADED, not imported: `NODE_OPTIONS=--import ./dist/telemetry/register.js`. Instrumentation
 * works by intercepting module loading, so a pipeline started from inside the application has
 * already missed the modules the application imported to get there.
 *
 * Opt-in twice over, and that is the point for a project other people deploy:
 *   - no NODE_OPTIONS  → this file is never loaded, and the SDK never enters the process;
 *   - no endpoint      → it loads, does nothing, and says so once.
 *
 * Nothing here can fail the process. A telemetry pipeline that refuses to start is a telemetry
 * pipeline that takes the service down with it, which is a strictly worse trade than blind.
 */
import { register } from 'node:module'
import { serviceIdentity, tracingRequested } from './identity.js'

const say = (message: string) =>
  process.stdout.write(JSON.stringify({ level: 'info', logger: 'telemetry', message }) + '\n')

if (!tracingRequested()) {
  say('OTEL_EXPORTER_OTLP_ENDPOINT is not set; tracing is off.')
} else {
  try {
    // ESM is not patched by the CommonJS hook. Registered BEFORE the instrumentations are created,
    // or the modules they mean to wrap are already resolved by the time the hook exists.
    register('import-in-the-middle/hook.mjs', import.meta.url)

    const [{ NodeSDK }, { resourceFromAttributes }, http, fastify, pg, ioredis, undici] =
      await Promise.all([
        import('@opentelemetry/sdk-node'),
        import('@opentelemetry/resources'),
        import('@opentelemetry/instrumentation-http'),
        import('@opentelemetry/instrumentation-fastify'),
        import('@opentelemetry/instrumentation-pg'),
        import('@opentelemetry/instrumentation-ioredis'),
        import('@opentelemetry/instrumentation-undici'),
      ])

    const identity = serviceIdentity()
    const sdk = new NodeSDK({
      // Left to the SDK's own environment detector wherever possible; named here only so a
      // deployment that sets nothing still produces a service that can be told apart.
      resource: resourceFromAttributes({
        ...(identity.service ? { 'service.name': identity.service } : {}),
        ...(identity.version ? { 'service.version': identity.version } : {}),
        ...(identity.env ? { 'deployment.environment': identity.env } : {}),
      }),
      traceExporter: await exporter(),
      instrumentations: [
        new http.HttpInstrumentation({
          // Health and metrics are polled every few seconds by things that are not users. Left in,
          // they are most of the trace volume and none of the signal.
          ignoreIncomingRequestHook: (request) => IGNORED.test(request.url ?? ''),
        }),
        new fastify.FastifyInstrumentation(),
        new pg.PgInstrumentation(),
        new ioredis.IORedisInstrumentation(),
        new undici.UndiciInstrumentation(),
      ],
    })

    sdk.start()
    say(`tracing on → ${process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? 'traces endpoint'}`)

    for (const signal of ['SIGTERM', 'SIGINT'] as const) {
      // A span reaches the collector when the batch is flushed, so a process that exits without
      // shutting the SDK down loses whatever it was still holding — including the last request.
      process.once(signal, () => {
        sdk.shutdown().catch(() => {}).finally(() => process.exit(0))
      })
    }
  } catch (err) {
    say(`tracing could not start, continuing without it: ${(err as Error).message}`)
  }
}

/** `/api/health`, `/metrics`, and the readiness variants of both. */
const IGNORED = /^\/(api\/)?(health|healthz|readyz|livez|metrics)\b/

/**
 * gRPC on 4317 or protobuf-over-HTTP on 4318, chosen the standard way. The packages do NOT read
 * `OTEL_EXPORTER_OTLP_PROTOCOL` for us — picking the wrong one is a pipeline that starts, reports
 * success, and delivers nothing.
 */
async function exporter() {
  const protocol = (process.env.OTEL_EXPORTER_OTLP_TRACES_PROTOCOL ||
    process.env.OTEL_EXPORTER_OTLP_PROTOCOL ||
    'grpc').toLowerCase()
  if (protocol.startsWith('http')) {
    const { OTLPTraceExporter } = await import('@opentelemetry/exporter-trace-otlp-proto')
    return new OTLPTraceExporter()
  }
  const { OTLPTraceExporter } = await import('@opentelemetry/exporter-trace-otlp-grpc')
  return new OTLPTraceExporter()
}
