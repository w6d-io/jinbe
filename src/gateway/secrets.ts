/**
 * Secrets never go through the console: they stay in the chart, as gateway env from a Kubernetes
 * Secret. The Gateway spec is rendered into a ConfigMap anyone in the namespace can read, so the
 * site-operator refuses any config key named client_secret, password, secret or token, at any depth
 * (site-operator internal/gateway secretKeys). jinbe applies the same rule first.
 *
 *   - Out: a secret key's value, and any value that looks like a credential (`Bearer …`,
 *     `Basic …`), reads `***`. The console shows it as "set by the platform".
 *   - In: a secret key may only come back as `***`, and is then dropped from the spec — the
 *     platform supplies it. A credential-looking value is refused, and so is a `vault:` string,
 *     which the operator refuses too (it has no Vault access). `***` elsewhere keeps what the
 *     Gateway already holds at that path, unless that is itself a credential (read from the live
 *     Oathkeeper config before any Gateway existed: it must move to the chart, not into the CR).
 */

export const MASK = '***'
export const SECRET_KEYS: readonly string[] = ['client_secret', 'password', 'secret', 'token']
const CREDENTIAL = /^(bearer|basic|token)\s+\S{8,}$/i

type Path = string[]
type Json = Record<string, unknown>

const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v)
export const isSecretKey = (k: string) => SECRET_KEYS.includes(k.toLowerCase())
export const looksLikeCredential = (v: unknown) => typeof v === 'string' && CREDENTIAL.test(v.trim())

function getAt(obj: unknown, path: Path): unknown {
  let cur = obj
  for (const p of path) {
    if (!isObject(cur)) return undefined
    cur = cur[p]
  }
  return cur
}

/** Every leaf of a config: its path and value (arrays are leaves). */
function leaves(obj: Json, base: Path = []): Array<[Path, unknown]> {
  return Object.entries(obj).flatMap(([k, v]) => (isObject(v) ? leaves(v, [...base, k]) : [[[...base, k], v] as [Path, unknown]]))
}

/** Paths whose own key is a secret key (the value may be an object: all of it is secret). */
function secretKeyPaths(obj: Json, base: Path = []): Path[] {
  return Object.entries(obj).flatMap(([k, v]) => {
    const here = [...base, k]
    if (isSecretKey(k)) return [here]
    return isObject(v) ? secretKeyPaths(v, here) : []
  })
}

export function maskConfig(config: Json | undefined): Json | undefined {
  if (!config) return config
  const out = structuredClone(config)
  for (const path of secretKeyPaths(out)) (getAt(out, path.slice(0, -1)) as Json)[path[path.length - 1]] = MASK
  for (const [path, v] of leaves(out)) {
    if (looksLikeCredential(v)) (getAt(out, path.slice(0, -1)) as Json)[path[path.length - 1]] = MASK
  }
  return out
}

export interface SecretIssue { path: string; code: 'secret_set_by_platform' | 'secret_in_config' | 'secret_nothing_to_keep'; message: string }

/** The config to write, or the issues that refuse it. */
export function resolveSecrets(incoming: Json | undefined, current: Json | undefined): { config: Json | undefined; issues: SecretIssue[] } {
  if (!incoming) return { config: incoming, issues: [] }
  const out = structuredClone(incoming)
  const issues: SecretIssue[] = []
  for (const path of secretKeyPaths(out)) {
    const parent = getAt(out, path.slice(0, -1)) as Json
    const key = path[path.length - 1]
    const at = path.join('.')
    if (parent[key] === MASK) delete parent[key]
    else issues.push({ path: at, code: 'secret_set_by_platform', message: `${at}: secrets are set by the platform (chart env from a Secret), not in the gateway configuration` })
  }
  const refused = new Set(issues.map((i) => i.path))
  for (const [path, v] of leaves(out)) {
    const at = path.join('.')
    if (refused.has(at)) continue
    const parent = getAt(out, path.slice(0, -1)) as Json
    const key = path[path.length - 1]
    if (v === MASK) {
      const kept = getAt(current, path)
      if (kept === undefined) issues.push({ path: at, code: 'secret_nothing_to_keep', message: `${at}: "***" keeps the saved value, and there is none` })
      else if (looksLikeCredential(kept)) issues.push({ path: at, code: 'secret_in_config', message: `${at}: the live gateway holds a credential here; move it to the chart (env from a Secret)` })
      else parent[key] = kept
    } else if (typeof v === 'string' && v.startsWith('vault:')) {
      issues.push({ path: at, code: 'secret_set_by_platform', message: `${at}: vault: references are not resolved (the operator has no Vault access); secrets are set by the platform (chart env from a Secret)` })
    } else if (looksLikeCredential(v)) {
      issues.push({ path: at, code: 'secret_in_config', message: `${at}: looks like a credential; the gateway configuration is readable — keep it in the chart (env from a Secret)` })
    }
  }
  return { config: out, issues }
}
