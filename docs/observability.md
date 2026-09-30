# Observability

Everything here is **off unless asked for**. jinbe is deployed by people who have no Grafana, no
Tempo, and no wish to acquire either; none of them should have to configure something to get
nothing. Every switch below has its absence as the OFF position, and no feature changes behaviour
when telemetry is off.

## What is measurable

| | how |
|---|---|
| Traces | OpenTelemetry, OTLP, opt-in twice (see below) |
| Log ↔ trace correlation | flat `trace_id` / `span_id` on every line, always on, costs nothing |
| Metrics | Prometheus on `/metrics`, unchanged |

## Traces

Preloaded rather than imported, because instrumentation works by intercepting module loading: a
pipeline started from inside the application has already missed the modules the application imported
to get there.

```sh
NODE_OPTIONS="--import ./dist/telemetry/register.js"
OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo.tempo.svc.cluster.local:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc          # or http/protobuf for 4318
OTEL_SERVICE_NAME=jinbe
OTEL_RESOURCE_ATTRIBUTES=service.version=1.2.3,deployment.environment=dev
```

**Two independent off switches.** Without `NODE_OPTIONS` the module is never loaded and the SDK
never enters the process. With it but without an endpoint, it loads, does nothing, and says so once.
Nothing in here can fail the process: a telemetry pipeline that refuses to start is one that takes
the service down with it.

Instrumented: HTTP (in and out), Fastify, Postgres, Redis, `fetch`. Health and metrics endpoints are
excluded from incoming traces — they are polled every few seconds by things that are not users, and
would be most of the volume and none of the signal.

`OTEL_EXPORTER_OTLP_PROTOCOL` is read by this code, not by the exporter packages. Picking the wrong
one gives a pipeline that starts, reports success, and delivers nothing.

## Log ↔ trace correlation

Every line carries `service`, `env`, `version` — read from the **same variables the SDK reads**, so a
line cannot be filed under a service the traces do not know — plus `trace_id` and `span_id` whenever
a span is active.

The field names are a **contract with the datasource**, not a style choice. Grafana joins a Loki
line to its Tempo trace with a derived field whose regex reads:

```
"trace_id":"(\w+)"
```

Flat, that spelling, compact JSON. A nested identifier, or one under another name, is one nothing
can join on. And the identifiers are **omitted** rather than zeroed when there is no span: a zeroed
trace id matches that regex and would link to a trace that never existed.

This half is always on. It needs no endpoint and no SDK — `trace.getActiveSpan()` simply returns
nothing when no provider is registered. A format that only appears once telemetry is configured is a
format nobody has looked at when it matters.

## Audit reads from Loki

`/api/audit/*` and the Home's activity and changes tiles read
Loki (`LOKI_URL`, pinned to `LOKI_NAMESPACE`). Every audit/v1 event is one JSON line on jinbe's
stdout with `"log_type":"audit"`; whether the collector turns that field into a Loki **label** is up
to the cluster, so how the reads find the audit stream is a setting:

| `LOKI_AUDIT_SELECTOR` | audit reads |
|---|---|
| `json` (default) | `{namespace="…", container="jinbe"} \|= "\"log_type\":\"audit\"" \| json \| log_type="audit" …` |
| `label` | `{log_type="audit", namespace="…"} \| json …` |

`json` works on any Loki: it reads only jinbe's container (`LOKI_AUDIT_CONTAINER`, default
`jinbe`), drops other lines on the raw text before parsing, and the parsed `log_type` field decides.
`label` is cheaper on large volumes but needs the collector to promote `log_type` for jinbe's
container; with `label` set and no such label, every audit read comes back empty. Switch to `label`
only once `{log_type="audit", namespace="…"}` returns lines in Grafana.

Beyond the selector, both modes build the same query — the org scope, the field filters, the
escaping of every caller value into one literal, the limits and the windows.

**What it costs.** A raw-line filter does not spare Loki the reading: in `json` mode every count
decompresses all of jinbe's lines in the window (auth-dev, 7 days: 5.5 M lines, 455 MB, for ~440
audit events). Facet and histogram counts are therefore asked as range queries at a fixed step
(`countsOver` in `audit/query/reader.ts`), which Loki's results cache keeps per interval: the first
view of a week reads it once (~1.3 s on auth-dev), a reload only the newest step (~0.1 s). `label`
mode removes the reading itself; it is the bigger win on any window nobody has asked for yet.

**Gateway decisions.** `GET /api/audit/access` (platform readers) counts the gateway's own
`Access request granted/denied` lines (`LOKI_GATEWAY_CONTAINER`, default `oathkeeper`) by subject and
host, and every hour jinbe copies those counts into the trail as `access.summary` events, one per
subject and host (`ACCESS_ROLLUP=off` stops it). Paths are not grouped on: they are open-ended.

## Known rough edge

`module.register()`, which the ESM instrumentation hook needs, is deprecated from Node 26 and prints
a warning at startup. `registerHooks()` is the replacement, but `import-in-the-middle` does not yet
ship a hook for it. The warning is noise, not a failure.
