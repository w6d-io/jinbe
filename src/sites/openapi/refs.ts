import { FORBIDDEN_KEYS, LIMITS, specError } from './limits.js'

/**
 * In-document `$ref` (`#/…` JSON pointers) only, and only where the importer reads: path items,
 * parameters, security schemes. Schemas are never resolved, so circular or fan-out schemas cost
 * nothing. Resolution returns the target by reference (no copy, no expansion); a chain is followed
 * at most LIMITS.refHops times and a cycle is an error. Anything that is not a local pointer
 * (`http:`, `file:`, a relative document) is refused, never fetched or read.
 */

type Json = unknown

const isObject = (v: Json): v is Record<string, Json> => v !== null && typeof v === 'object' && !Array.isArray(v)

/** RFC 6901 pointer tokens of a `#/…` fragment (URI-decoded, `~1` → `/`, `~0` → `~`). */
function pointerTokens(ref: string): string[] {
  if (!ref.startsWith('#/')) throw specError('external_ref', `only in-document references (#/…) are followed, not '${ref.slice(0, 80)}'`)
  let fragment: string
  try {
    fragment = decodeURIComponent(ref.slice(2))
  } catch {
    throw specError('invalid_ref', `unreadable reference '${ref.slice(0, 80)}'`)
  }
  return fragment.split('/').map((t) => t.replaceAll('~1', '/').replaceAll('~0', '~'))
}

function lookup(root: Json, ref: string): Json {
  let node = root
  for (const token of pointerTokens(ref)) {
    if (FORBIDDEN_KEYS.has(token)) throw specError('forbidden_key', `reference through '${token}'`)
    if (Array.isArray(node)) {
      const i = /^(0|[1-9][0-9]{0,6})$/.test(token) ? Number(token) : -1
      if (i < 0 || i >= node.length) throw specError('ref_not_found', `reference '${ref.slice(0, 120)}' does not resolve`)
      node = node[i]
    } else if (isObject(node) && Object.hasOwn(node, token)) {
      node = node[token]
    } else {
      throw specError('ref_not_found', `reference '${ref.slice(0, 120)}' does not resolve`)
    }
  }
  return node
}

/** The node itself, or what its `$ref` chain points at. Siblings of `$ref` are ignored (3.0 rules). */
export function deref(root: Json, node: Json): Json {
  const seen = new Set<string>()
  let current = node
  while (isObject(current) && Object.hasOwn(current, '$ref')) {
    const ref = current.$ref
    if (typeof ref !== 'string') throw specError('invalid_ref', '$ref must be a string')
    if (seen.has(ref)) throw specError('ref_cycle', `reference cycle through '${ref.slice(0, 120)}'`)
    if (seen.size >= LIMITS.refHops) throw specError('ref_too_deep', `more than ${LIMITS.refHops} chained references`)
    seen.add(ref)
    current = lookup(root, ref)
  }
  return current
}

/** `deref`, then the result must be an object (a path item, a parameter, a security scheme). */
export function derefObject(root: Json, node: Json, what: string): Record<string, Json> | null {
  const out = deref(root, node)
  if (out === undefined || out === null) return null
  if (!isObject(out)) throw specError('invalid_spec', `${what} must be an object`)
  return out
}
