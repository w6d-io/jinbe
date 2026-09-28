import { parseDocument } from 'yaml'
import { FORBIDDEN_KEYS, LIMITS, SpecError, specError } from './limits.js'
import { extract, type ParsedSpec } from './extract.js'

/**
 * Bytes → tree → ParsedSpec, synchronously. Runs inside the parse worker (load.ts), which bounds its
 * time and memory; exported for the worker and for tests only.
 *
 * JSON through JSON.parse; YAML through yaml@2 with the core schema (no `!!js/*` or custom tags: a
 * tag it does not know is refused, not read as a string), `<<` merge keys off, at most
 * LIMITS.yamlAliases alias expansions, duplicate keys refused, one document. The tree is then walked
 * once, iteratively: depth, node count, string length, and the prototype keys.
 */

export type SpecFormat = 'auto' | 'json' | 'yaml'

const short = (message: string) => message.split('\n')[0].slice(0, 200)

function parseYaml(src: string): unknown {
  const doc = parseDocument(src, { schema: 'core', merge: false, uniqueKeys: true, strict: true, prettyErrors: false })
  if (doc.errors.length > 0) throw specError('unreadable_spec', `not valid YAML: ${short(doc.errors[0].message)}`)
  if (doc.warnings.length > 0) throw specError('unreadable_spec', `refused YAML: ${short(doc.warnings[0].message)}`)
  try {
    return doc.toJS({ maxAliasCount: LIMITS.yamlAliases })
  } catch (e) {
    const message = (e as Error).message ?? ''
    if (message.includes('alias')) throw specError('too_many_aliases', `more than ${LIMITS.yamlAliases} YAML alias expansions`)
    throw specError('unreadable_spec', `not valid YAML: ${short(message)}`)
  }
}

/** Depth, size and key checks over the whole tree, without recursion. */
export function walk(root: unknown): void {
  const stack: Array<[unknown, number]> = [[root, 0]]
  let nodes = 0
  while (stack.length > 0) {
    const [node, depth] = stack.pop()!
    if (++nodes > LIMITS.nodes) throw specError('too_many_nodes', `more than ${LIMITS.nodes} values`)
    if (typeof node === 'string') {
      if (node.length > LIMITS.string) throw specError('string_too_long', `a value longer than ${LIMITS.string} characters`)
      continue
    }
    if (node === null || typeof node !== 'object') continue
    if (depth >= LIMITS.depth) throw specError('too_deep', `nested deeper than ${LIMITS.depth} levels`)
    if (Array.isArray(node)) {
      for (const v of node) stack.push([v, depth + 1])
      continue
    }
    for (const key of Object.keys(node)) {
      if (FORBIDDEN_KEYS.has(key)) throw specError('forbidden_key', `the key '${key}' is not allowed`)
      if (key.length > LIMITS.string) throw specError('string_too_long', `a key longer than ${LIMITS.string} characters`)
      stack.push([(node as Record<string, unknown>)[key], depth + 1])
    }
  }
}

export function parseTree(src: string, format: SpecFormat = 'auto'): unknown {
  if (typeof src !== 'string' || src.trim() === '') throw specError('unreadable_spec', 'the spec is empty')
  if (Buffer.byteLength(src, 'utf8') > LIMITS.bytes) throw specError('spec_too_large', `larger than ${LIMITS.bytes / 1024 / 1024} MiB`)
  const json = format === 'json' || (format === 'auto' && src.trimStart().startsWith('{'))
  let tree: unknown
  try {
    tree = json ? JSON.parse(src) : parseYaml(src)
  } catch (e) {
    if (e instanceof SpecError) throw e
    throw specError('unreadable_spec', `not valid ${json ? 'JSON' : 'YAML'}: ${short((e as Error).message ?? '')}`)
  }
  walk(tree)
  return tree
}

export function parseSpecSync(src: string, format: SpecFormat = 'auto'): ParsedSpec {
  return extract(parseTree(src, format))
}
