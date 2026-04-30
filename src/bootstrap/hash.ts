import { createHash } from 'crypto'

/**
 * Stable, content-addressable hash of arbitrary JSON values.
 *
 * Used to detect drift in built-in oathkeeper rules and route_map without
 * requiring a manual SCHEMA_VERSION bump for every code-only change.
 *
 * Object keys are sorted recursively so two semantically identical objects
 * with different key orderings produce the same hash.
 */
export function canonicalHash(value: unknown): string {
  const canonical = canonicalize(value)
  const json = JSON.stringify(canonical)
  return 'sha256:' + createHash('sha256').update(json).digest('hex')
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(canonicalize)
  const obj = value as Record<string, unknown>
  const sortedKeys = Object.keys(obj).sort()
  const out: Record<string, unknown> = {}
  for (const k of sortedKeys) out[k] = canonicalize(obj[k])
  return out
}
