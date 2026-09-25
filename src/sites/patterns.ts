/**
 * Route paths → Oathkeeper `regexp` match URLs, and the overlap question between two paths.
 *
 * Paths use the route-map grammar (`/api/:id`, `/assets/:any*`), the same one the policy reads, so a
 * gate's pattern and the permission rows it serves are built from one source. The strategy's `<…>`
 * delimiters are counted by Oathkeeper's compiler, so no generated regex may contain `<` or `>`
 * (that rules out look-behind; negative look-ahead is fine).
 *
 * Nothing here is the authority on what Oathkeeper will match — gatekit is. This is the generator;
 * gatekit compiles and probes what it generates before anything is written.
 */

const ANY = ':any*'

export function escapeRegex(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')
}

const isParam = (segment: string) => segment.startsWith(':')

/** `/api/:id` → `/api/[^/]+`; `/assets/:any*` → `/assets(?:/.*)?` (the prefix itself and below). */
export function pathRegex(path: string): string {
  const segments = path.split('/')
  const any = segments.at(-1) === ANY
  const fixed = any ? segments.slice(0, -1) : segments
  const body = fixed.map((s) => (isParam(s) ? '[^/]+' : escapeRegex(s))).join('/')
  if (!any) return body
  return body === '' ? '/.*' : `${body}(?:/.*)?`
}

const segmentsOverlap = (a: string, b: string) => isParam(a) || isParam(b) || a === b

/** Whether some request path is matched by both route paths, at any rank. */
export function pathsOverlap(a: string, b: string): boolean {
  const pa = a.split('/')
  const pb = b.split('/')
  const anyA = pa.at(-1) === ANY
  const anyB = pb.at(-1) === ANY
  const fa = anyA ? pa.slice(0, -1) : pa
  const fb = anyB ? pb.slice(0, -1) : pb
  if (!anyA && !anyB) return fa.length === fb.length && fa.every((s, i) => segmentsOverlap(s, fb[i]))
  // `:any*` matches its prefix and anything below; the shorter fixed part must fit inside the other.
  if (anyA && !anyB && fb.length < fa.length) return false
  if (anyB && !anyA && fa.length < fb.length) return false
  const depth = Math.min(fa.length, fb.length)
  return fa.slice(0, depth).every((s, i) => segmentsOverlap(s, fb[i]))
}

// The site-operator only accepts a literal host right after the scheme, followed by "/", so a Site
// can only ever claim its own host (site-operator validate.matchHostOK). Regex starts after that "/".
const SCHEME = '<https?>://'
const afterSlash = (regex: string) => regex.slice(1)

/** A gate serving exactly these paths. */
export function enumeratedMatchUrl(host: string, paths: readonly string[]): string {
  const alternatives = [...new Set(paths.map((p) => afterSlash(pathRegex(p))))].sort()
  return `${SCHEME}${host}/<(?:${alternatives.join('|')})>`
}

/** The catch-all gate: everything under `prefix` (or the whole host) except the other gates' paths. */
export function catchAllMatchUrl(host: string, prefix: string | undefined, excluded: readonly string[]): string {
  const base = prefix ? `${escapeRegex(prefix.slice(1))}(?:/.*)?` : '.*'
  const alternatives = [...new Set(excluded.map((p) => afterSlash(pathRegex(p))))].sort()
  const guard = alternatives.length > 0 ? `(?!(?:${alternatives.join('|')})$)` : ''
  return `${SCHEME}${host}/<${guard}${base}>`
}

/** A concrete URL a path matches — the probe gatekit is asked about. */
export function examplePath(path: string): string {
  return path
    .split('/')
    .map((s) => (s === ANY ? 'probe/x' : isParam(s) ? 'x1' : s))
    .join('/')
}
