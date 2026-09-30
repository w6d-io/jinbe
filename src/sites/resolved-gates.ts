import { SPEC_KEY, type GatewaySpec } from '../gateway/kube-gateway.js'
import type { HandlerKind } from '../gateway/catalog.js'
import type { SiteCrGate } from './render.js'

/**
 * What each gate handler will actually run with: the rule's own config merged over the platform's
 * global config for that handler (the Gateway spec), the way Oathkeeper builds it — a JSON merge
 * patch (RFC 7386, oathkeeper `PipelineConfig`): objects merge key by key, anything else in the rule
 * replaces the global value, and a `null` in the rule removes it.
 *
 * Each leaf of the result says where it came from: `explicit` (the rule sets it — the site's intent,
 * or what render writes for it) or `default` (the platform's handler config). Nested keys are dotted
 * (`headers.X-User`); an array is one leaf.
 */

type Json = Record<string, unknown>
const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v)

export type FieldSource = 'explicit' | 'default'

export interface ResolvedHandler {
  kind: HandlerKind
  handler: string
  /** Whether the platform enables the handler; null when the platform does not declare it. */
  enabled: boolean | null
  config: Json
  fields: Record<string, FieldSource>
}

export interface ResolvedGate {
  gate: string
  handlers: ResolvedHandler[]
}

/** RFC 7386 merge patch of `patch` over `target`. */
export function mergePatch(target: unknown, patch: unknown): unknown {
  if (!isObject(patch)) return patch
  const out: Json = isObject(target) ? { ...target } : {}
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) delete out[key]
    else out[key] = mergePatch(out[key], value)
  }
  return out
}

function sources(effective: Json, explicit: unknown, prefix = ''): Record<string, FieldSource> {
  const out: Record<string, FieldSource> = {}
  for (const [key, value] of Object.entries(effective)) {
    const path = prefix ? `${prefix}.${key}` : key
    const own = isObject(explicit) ? explicit[key] : undefined
    if (isObject(value) && Object.keys(value).length > 0) {
      Object.assign(out, isObject(own) ? sources(value, own, path) : leaves(value, path, 'default'))
    } else {
      out[path] = own !== undefined ? 'explicit' : 'default'
    }
  }
  return out
}

function leaves(value: Json, prefix: string, source: FieldSource): Record<string, FieldSource> {
  const out: Record<string, FieldSource> = {}
  for (const [key, v] of Object.entries(value)) {
    const path = `${prefix}.${key}`
    if (isObject(v) && Object.keys(v).length > 0) Object.assign(out, leaves(v, path, source))
    else out[path] = source
  }
  return out
}

export function resolveHandler(kind: HandlerKind, handler: { handler: string; config?: Json }, spec: GatewaySpec): ResolvedHandler {
  const platform = spec[SPEC_KEY[kind]]?.[handler.handler]
  const defaults = isObject(platform?.config) ? platform.config : {}
  const effective = mergePatch(defaults, handler.config ?? {}) as Json
  return {
    kind,
    handler: handler.handler,
    enabled: platform ? platform.enabled === true : null,
    config: effective,
    fields: sources(effective, handler.config ?? {}),
  }
}

/** Every handler of every rendered gate (pre-flight gates included), resolved against the platform. */
export function resolveGates(gates: readonly SiteCrGate[], spec: GatewaySpec): ResolvedGate[] {
  return gates.map((gate) => ({
    gate: gate.name,
    handlers: [
      ...gate.authenticators.map((h) => resolveHandler('authenticator', h, spec)),
      resolveHandler('authorizer', gate.authorizer, spec),
      ...gate.mutators.map((h) => resolveHandler('mutator', h, spec)),
      ...(gate.errors ?? []).map((h) => resolveHandler('error', h, spec)),
    ],
  }))
}
