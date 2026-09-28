import type { Gate, Handler } from './schemas.js'

// A gate's error handlers, and the proof that no refusal finds two of them responsible.
//
// Oathkeeper v25.4.0 (proxy/request_handler.go HandleError) asks EVERY handler of the rule whether
// its `when` matches: two matches is a 500 ("Found more than one error handlers…"), none falls
// through to the global `errors.fallback` list, where the first match wins. A rule handler's config
// is the global one deep-merged with the rule's (koanf maps.Merge), and an array replaces rather
// than merges: a handler that omits `when` inherits the environment's, one that sets it — even to
// [] — owns it. So every handler rendered here carries its own `when`.
//
// How a `when` matches (pipeline/errors/when.go): entries are OR'd. In one entry, `error` lists
// status texts — the config schema accepts only the four in WHEN_ERRORS, and an error without a
// status code counts as internal_server_error — AND'd with the request part. A missing Accept
// header reads as application/octet-stream. A handler type `*/*` matches any Accept, `type/*`
// any subtype, anything else must appear verbatim; a request's `*/*` matches only a handler's
// `*/*`.
//
// So no positive `when` tells "Accept: */*" (curl, fetch()) from a browser, whose Accept carries
// */* too: those refusals match nothing here and take the platform fallback (json by default).
// Likewise one Accept naming both text/html and application/json matches both handlers; no client
// we know of sends that.

/** The error names Oathkeeper's config schema accepts in a `when`. */
export const WHEN_ERRORS = ['unauthorized', 'forbidden', 'not_found', 'internal_server_error'] as const

/** What a browser navigation sends; what API clients send (octet-stream: no Accept header at all). */
const BROWSER = ['text/html']
const MACHINE = ['application/json', 'application/problem+json', 'application/octet-stream']

interface When {
  error?: string[]
  request?: { header?: { accept?: string[]; content_type?: string[] }; remote_ip?: unknown }
}

const onBrowser = (error: string[]): When => ({ error, request: { header: { accept: BROWSER } } })

/** The platform's sign-in redirect (its `to` comes from the gateway config), for browsers only. */
const loginRedirect = (error: string[]): Handler => ({ handler: 'redirect', config: { when: [onBrowser(error)] } })

/** json for every refusal a browser redirect does not take. */
const jsonRest: Handler = {
  handler: 'json',
  config: { when: [{ error: ['not_found', 'internal_server_error'] }, { error: ['unauthorized', 'forbidden'], request: { header: { accept: MACHINE } } }] },
}

/**
 * Browser gates of a 2FA site send `forbidden` to login-ui /access (step-up, enrol, or a branded
 * no-access page — it asks jinbe which). Oathkeeper's remote_json cannot pass the policy's reason
 * through, so the redirect is per rule, on `forbidden` only.
 */
function accessRedirect(site: string, accessUrl: string): Handler {
  const to = new URL(accessUrl)
  to.searchParams.set('site', site)
  return { handler: 'redirect', config: { to: to.toString(), return_to_query_param: 'return_to', when: [onBrowser(['forbidden'])] } }
}

/** A gate's `errors` as rule handlers; undefined leaves the refusal to the platform fallback list. */
export function errorHandlers(errors: Gate['errors'], site: string, accessUrl?: string): Handler[] | undefined {
  if (errors === 'platform') return undefined
  // An explicit empty `when` replaces the global one: json answers every refusal.
  if (errors === 'api') return [{ handler: 'json', config: { when: [] } }]
  if (errors === 'website') {
    return accessUrl
      ? [accessRedirect(site, accessUrl), loginRedirect(['unauthorized']), jsonRest]
      : [loginRedirect(['unauthorized', 'forbidden']), jsonRest]
  }
  return errors
}

// ── the model of Oathkeeper's matching ─────────────────────────────────────────────────────────

const TOKEN = /[!#$%&'*+\-.^_`|~0-9A-Za-z/]/

/** github.com/golang/gddo httputil/header.ParseAccept: a parameter other than q ends the parse. */
export function parseAccept(value: string): string[] {
  const out: string[] = []
  let s = value
  const skipSpace = () => { s = s.replace(/^[ \t\r\n]+/, '') }
  for (;;) {
    let i = 0
    while (i < s.length && TOKEN.test(s[i])) i++
    const type = s.slice(0, i)
    if (!type) return out
    s = s.slice(i)
    skipSpace()
    if (s.startsWith(';')) {
      s = s.slice(1)
      skipSpace()
      const q = /^q=[01](\.[0-9]*)?/.exec(s)
      if (!q) return out
      s = s.slice(q[0].length)
    }
    out.push(type)
    skipSpace()
    if (!s.startsWith(',')) return out
    s = s.slice(1)
    skipSpace()
  }
}

/** when.go matchesAcceptMIME. */
export function acceptMatches(requestAccept: string, handlerTypes: string[]): boolean {
  const wanted = parseAccept(handlerTypes.join(','))
  return parseAccept(requestAccept).some((a) => wanted.some((m) =>
    m === '*/*' || (m.endsWith('/*') && m.slice(0, -2) === a.split('/')[0]) || a === m))
}

/**
 * when.go matches, for an error name and an Accept header (undefined: none sent). Content-Type
 * and remote-IP conditions are assumed to match, so the answer errs towards "responsible".
 */
export function whenMatches(when: unknown, error: string, accept: string | undefined): boolean {
  if (!Array.isArray(when) || when.length === 0) return true
  return (when as When[]).some((w) => {
    if (w.error?.length && !w.error.includes(error)) return false
    const types = w.request?.header?.accept
    return !types?.length || acceptMatches(accept || 'application/octet-stream', types)
  })
}

/** Accept headers real clients send, beside every type the handlers name. */
const CLIENT_ACCEPTS: Array<[string, string | undefined]> = [
  ['no Accept header', undefined],
  ['Accept: */*', '*/*'],
  ['a Chrome navigation', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'],
  ['a Firefox navigation', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8'],
  ['a Safari navigation', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
  ['axios', 'application/json, text/plain, */*'],
]

export interface ErrorProbe { error: string; accept: string | undefined; label: string }

/** The (error, Accept) grid a handler set is checked on. */
export function errorProbes(handlers: Handler[]): ErrorProbe[] {
  const named = new Set<string>()
  for (const h of handlers) {
    const when = h.config?.when
    if (!Array.isArray(when)) continue
    for (const w of when as When[]) {
      for (const t of parseAccept((w.request?.header?.accept ?? []).join(','))) {
        named.add(t)
        if (t.includes('/') && !t.startsWith('*')) named.add(`${t.split('/')[0]}/*`)
      }
    }
  }
  const accepts: Array<[string, string | undefined]> = [...CLIENT_ACCEPTS, ...[...named].map((t): [string, string] => [`Accept: ${t}`, t])]
  return WHEN_ERRORS.flatMap((error) => accepts.map(([label, accept]) => ({ error, accept, label })))
}

/**
 * Why this set of rule error handlers can answer one refusal twice (a 500 at the gateway), or use
 * a `when` Oathkeeper refuses. A handler without its own `when` takes the gateway's, which a site
 * cannot see: next to another handler, it is taken to match everything.
 */
export function errorHandlerProblems(handlers: Handler[]): string[] {
  const problems: string[] = []
  handlers.forEach((h, i) => {
    const when = h.config?.when
    if (when !== undefined && !Array.isArray(when)) problems.push(`error handler #${i + 1} (${h.handler}): when must be a list`)
    for (const w of Array.isArray(when) ? (when as When[]) : []) {
      const bad = (w.error ?? []).filter((e) => !(WHEN_ERRORS as readonly string[]).includes(e))
      if (bad.length > 0) problems.push(`error handler #${i + 1} (${h.handler}): Oathkeeper knows no error '${bad.join("', '")}' (only ${WHEN_ERRORS.join(', ')})`)
    }
  })
  if (handlers.length < 2) return problems
  for (const probe of errorProbes(handlers)) {
    const hit = handlers.flatMap((h, i) => (whenMatches(h.config?.when, probe.error, probe.accept) ? [`#${i + 1} (${h.handler})`] : []))
    if (hit.length > 1) {
      problems.push(`error handlers ${hit.join(' and ')} both answer ${probe.error} for ${probe.label}; Oathkeeper then fails with 500 — give each handler a when that the others do not cover`)
      break
    }
  }
  return problems
}
