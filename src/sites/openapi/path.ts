import { LIMITS } from './limits.js'

/**
 * OpenAPI path templates → route paths (`/invoices/{id}` → `/invoices/:id`), by a linear tokenizer:
 * no regular expression ever runs over the spec's text, so a path cannot be a ReDoS. A literal
 * segment must use the route-path charset (schemas.ts `routePath`); a segment is either a literal
 * or exactly `{name}`. A partial template (`/report.{fmt}`, `{a}-{b}`) is offered as one whole-segment
 * `:param`, flagged `broadened` (it then matches more than the spec says). Anything else — `%`, `*`,
 * `(`, `:`, `.`/`..` segments — is `unsupported_path`: skipped, to be written by hand.
 */

export type PathResult =
  | { ok: true; path: string; params: string[]; broadened: boolean }
  | { ok: false; code: 'unsupported_path'; reason: string }

const unsupported = (reason: string): PathResult => ({ ok: false, code: 'unsupported_path', reason })

const isAlpha = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122)
const isDigit = (c: number) => c >= 48 && c <= 57
// A-Z a-z 0-9 . _ ~ @ -   (schemas.ts routePath literal charset)
const isLiteralChar = (c: number) => isAlpha(c) || isDigit(c) || c === 46 || c === 95 || c === 126 || c === 64 || c === 45

/** `^[A-Za-z_][A-Za-z0-9_]{0,63}$`, checked char by char. */
export function isParamName(s: string): boolean {
  if (s.length < 1 || s.length > 64) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (!(isAlpha(c) || c === 95 || (i > 0 && isDigit(c)))) return false
  }
  return true
}

function isLiteral(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (!isLiteralChar(s.charCodeAt(i))) return false
  return s !== '.' && s !== '..'
}

/** The `{names}` of a segment with templates, or null when its braces are not simple and balanced. */
function templateNames(segment: string): string[] | null {
  const names: string[] = []
  let i = 0
  while (i < segment.length) {
    const open = segment.indexOf('{', i)
    const strayClose = segment.indexOf('}', i)
    if (open === -1) return strayClose === -1 && isLiteral(segment.slice(i)) ? names : null
    if (strayClose !== -1 && strayClose < open) return null
    if (open > i && !isLiteral(segment.slice(i, open))) return null
    const close = segment.indexOf('}', open + 1)
    if (close === -1) return null
    const name = segment.slice(open + 1, close)
    if (!isParamName(name)) return null
    names.push(name)
    i = close + 1
  }
  return names
}

/** Join a base path (servers / basePath) and a spec path; `//` collapsed, no trailing slash. */
export function joinPaths(base: string, path: string): string {
  const parts = `${base}/${path}`.split('/').filter((s) => s !== '')
  return `/${parts.join('/')}`
}

export function toRoutePath(specPath: string): PathResult {
  if (specPath.length > LIMITS.pathLength) return unsupported(`longer than ${LIMITS.pathLength} characters`)
  if (!specPath.startsWith('/')) return unsupported('a path must start with /')
  const segments = specPath.split('/').filter((s) => s !== '')
  if (segments.length > LIMITS.segments) return unsupported(`more than ${LIMITS.segments} segments`)
  const out: string[] = []
  const params: string[] = []
  let broadened = false
  for (const segment of segments) {
    if (!segment.includes('{') && !segment.includes('}')) {
      if (!isLiteral(segment)) return unsupported(`segment '${segment.slice(0, 40)}' has characters a route path cannot hold`)
      out.push(segment)
      continue
    }
    const names = templateNames(segment)
    if (!names || names.length === 0) return unsupported(`segment '${segment.slice(0, 40)}' is not a simple {param}`)
    const whole = names.length === 1 && segment === `{${names[0]}}`
    if (!whole) broadened = true
    // A partial template becomes one :param named after its first variable.
    const name = names[0]
    if (params.includes(name)) return unsupported(`parameter '${name}' appears twice`)
    params.push(name)
    out.push(`:${name}`)
  }
  if (params.length > LIMITS.params) return unsupported(`more than ${LIMITS.params} parameters`)
  return { ok: true, path: `/${out.join('/')}`, params, broadened }
}

/** The shape of a route path: every `:param` the same, so `/a/:id` and `/a/:name` are one route. */
export const shapeOf = (routePath: string) => routePath.split('/').map((s) => (s.startsWith(':') ? ':' : s)).join('/')
