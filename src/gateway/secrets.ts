import type { FieldMeta, HandlerMeta } from './catalog.js'

/**
 * Secrets in handler config never leave jinbe and never enter the Gateway CR in clear.
 *
 *   - Out: every secret leaf that is not a Vault reference reads `***`. A reference
 *     (`vault:<path>#<key>`) names where the secret lives, not the secret, and is shown.
 *   - In: a secret leaf must be a Vault reference, empty, or `***` — which keeps the value the CR
 *     already holds at that exact path. `***` where the CR holds nothing is refused: there is
 *     nothing to keep. So is a clear value, and so is `***` over a value read from the live
 *     Oathkeeper config (no Gateway yet): keeping it would copy a clear secret into the CR.
 *
 * The site-operator resolves references into a Secret the gateway reads, never into its ConfigMap.
 */

export const MASK = '***'
const VAULT_REF = /^vault:[A-Za-z0-9_./-]+#[A-Za-z0-9_.-]+$/

export const isVaultRef = (v: unknown): v is string => typeof v === 'string' && VAULT_REF.test(v)

type Path = string[]
type Json = Record<string, unknown>

const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v)

function getAt(obj: unknown, path: Path): unknown {
  let cur = obj
  for (const p of path) {
    if (!isObject(cur)) return undefined
    cur = cur[p]
  }
  return cur
}

function setAt(obj: Json, path: Path, value: unknown): void {
  let cur = obj
  path.slice(0, -1).forEach((p) => {
    if (!isObject(cur[p])) cur[p] = {}
    cur = cur[p] as Json
  })
  cur[path[path.length - 1]] = value
}

/** The concrete secret leaves present in `config`: a kv field contributes one per entry. */
export function secretLeaves(meta: HandlerMeta | undefined, config: Json | undefined): Path[] {
  if (!meta || !config) return []
  return meta.fields.filter((f: FieldMeta) => f.secret).flatMap((f) => {
    const base = f.key.split('.')
    if (f.type !== 'kv') return getAt(config, base) === undefined ? [] : [base]
    const map = getAt(config, base)
    return isObject(map) ? Object.keys(map).map((k) => [...base, k]) : []
  })
}

export function maskConfig(meta: HandlerMeta | undefined, config: Json | undefined): Json | undefined {
  if (!config) return config
  const out = structuredClone(config)
  for (const path of secretLeaves(meta, out)) {
    const v = getAt(out, path)
    if (typeof v === 'string' && v !== '' && !isVaultRef(v)) setAt(out, path, MASK)
  }
  return out
}

export interface SecretIssue { path: string; code: 'secret_not_a_vault_ref' | 'secret_nothing_to_keep'; message: string }

/**
 * The config to write: `***` leaves replaced by what `current` holds. Returns the issues instead
 * when any secret leaf is unacceptable.
 */
export function resolveSecrets(
  meta: HandlerMeta | undefined,
  incoming: Json | undefined,
  current: Json | undefined,
  currentIsCr: boolean,
): { config: Json | undefined; issues: SecretIssue[] } {
  if (!incoming) return { config: incoming, issues: [] }
  const out = structuredClone(incoming)
  const issues: SecretIssue[] = []
  for (const path of secretLeaves(meta, out)) {
    const v = getAt(out, path)
    const at = path.join('.')
    if (v === '' || v === null || isVaultRef(v)) continue
    if (v === MASK) {
      const kept = getAt(current, path)
      if (kept === undefined || kept === '') {
        issues.push({ path: at, code: 'secret_nothing_to_keep', message: `${at}: "***" keeps the saved value, and there is none; give a vault:<path>#<key> reference` })
      } else if (!currentIsCr && !isVaultRef(kept)) {
        issues.push({ path: at, code: 'secret_not_a_vault_ref', message: `${at}: the live gateway holds this secret in clear; replace it with a vault:<path>#<key> reference` })
      } else {
        setAt(out, path, kept)
      }
      continue
    }
    issues.push({ path: at, code: 'secret_not_a_vault_ref', message: `${at}: secrets are accepted only as vault:<path>#<key> references` })
  }
  return { config: out, issues }
}
