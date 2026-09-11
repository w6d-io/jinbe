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
| Bundle propagation | which revision each authorization engine has actually activated |

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

## Bundle propagation

The policy bundle is **pulled**, which is what lets this service be down while decisions carry on —
and what made propagation unobservable. A change was committed when the write returned and enforced
at some unknown point inside the engine's polling window.

Point the engine's status plugin at this service and the window becomes a fact:

```
--set=status.service=<the same service already used for bundles>
```

It reports after every activation, with the credential it already fetches the bundle with, so there
is no second secret. Then:

```
GET /api/opa/propagation
{
  "serving": "d592a18625498518",
  "engines": [{ "id": "…", "revision": "d592a18625498518", "activatedAt": "…", "current": true }],
  "inSync": { "current": 2, "reporting": 2 },
  "settled": true
}
```

`settled` is true only when at least one engine reports **and** every one of them holds the served
revision. No engine reporting is *not known*, never *settled*: the two must not look alike.

Presence is judged on having reported recently, not on asking Kubernetes how many replicas there
should be — this service holds no permission to read pods, and a count derived from a reporter that
has gone quiet would claim a coverage nobody can observe.

**Measured cost**, OPA 1.19: each report is ~59 KB and arrives every few seconds per engine, because
OPA embeds its whole Prometheus registry in it. `status.prometheus=false` does **not** remove it.
The route accepts it and drops everything but the revision — refusing it would only make the engine
log an upload failure forever over a field nobody reads.

## Known rough edge

`module.register()`, which the ESM instrumentation hook needs, is deprecated from Node 26 and prints
a warning at startup. `registerHooks()` is the replacement, but `import-in-the-middle` does not yet
ship a hook for it. The warning is noise, not a failure.
