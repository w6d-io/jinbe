import { connect } from 'node:tls'
import type { Access, Site } from './schemas.js'
import { examplePath } from './patterns.js'

/**
 * The outside view of a published site, from jinbe: one anonymous request per route to the public
 * URL (sequential, 5 s each, at most PROBE_MAX_ROUTES and within PROBE_BUDGET_MS in all, so a verify
 * answers inside an MCP client's ~60 s tool timeout), the TLS certificate the host presents, and —
 * only when asked — one WAF check. Every failure is an answer: no egress from jinbe is "probe
 * unavailable", never a thrown error.
 *
 * Nothing here writes: GET or HEAD when the route has one, else its first method with no body. A
 * PUBLIC route with neither is not probed at all (an empty write would reach the service); a
 * protected one is, since the gateway must refuse it before the service sees it.
 */

export const PROBE_TIMEOUT_MS = 5000
export const PROBE_MAX_ROUTES = 50
/** The time all probes of one verify may take; a probe that could run past it is not sent. */
export const PROBE_BUDGET_MS = 25_000
const UA = 'jinbe-site-verify/1'

export interface ProbeResponse { status: number; location: string | null }
export interface TlsReport { authorized: boolean; validTo: string | null; error: string | null }

/** Egress seam (tests replace it). */
export interface ProbeTransport {
  request(method: string, url: string): Promise<ProbeResponse>
  tls(host: string): Promise<TlsReport>
}

const defaultTransport: ProbeTransport = {
  async request(method, url) {
    const res = await fetch(url, { method, redirect: 'manual', headers: { 'user-agent': UA }, signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) })
    await res.body?.cancel().catch(() => {})
    return { status: res.status, location: res.headers.get('location') }
  },
  tls(host) {
    return new Promise((resolve) => {
      const socket = connect({ host, port: 443, servername: host, timeout: PROBE_TIMEOUT_MS, rejectUnauthorized: false })
      const done = (r: TlsReport) => { socket.destroy(); resolve(r) }
      socket.once('secureConnect', () => {
        const cert = socket.getPeerCertificate()
        done({ authorized: socket.authorized, validTo: cert?.valid_to ? new Date(cert.valid_to).toISOString() : null, error: socket.authorized ? null : String(socket.authorizationError ?? 'untrusted') })
      })
      socket.once('timeout', () => done({ authorized: false, validTo: null, error: 'timeout' }))
      socket.once('error', (err) => done({ authorized: false, validTo: null, error: (err as NodeJS.ErrnoException).code ?? err.message }))
    })
  },
}

let transport: ProbeTransport = defaultTransport

/** Test seam. */
export function setProbeTransport(t: ProbeTransport | null): void {
  transport = t ?? defaultTransport
}
export const probeTransport = () => transport

export type Expectation = 'protected' | 'public' | 'denied'
export type ProbeVerdict = 'ok' | 'exposed' | 'unexpected' | 'unreachable' | 'skipped'

export interface ProbeTarget { route: string; methods: readonly string[]; path: string; access: Access }

export interface ProbeResult {
  route: string
  method: string
  url: string
  expect: Expectation
  status: number | null
  location?: string
  verdict: ProbeVerdict
  /** error: a protected route answered anonymously; warn: something else than expected. */
  level: 'ok' | 'error' | 'warn'
  message: string
}

export interface ProbeReport {
  available: boolean
  reason?: string
  results: ProbeResult[]
  /** Routes not requested: past PROBE_MAX_ROUTES, or past the time budget. */
  notProbed: string[]
  /** Set when the time budget, not the route cap, left routes out. */
  stoppedBy?: 'budget'
}

const expectationOf = (a: Access): Expectation => (a.kind === 'public' ? 'public' : a.kind === 'deny' ? 'denied' : 'protected')

/** The method a probe sends: GET, HEAD, else the first; null for a public route that only writes. */
export function probeMethod(t: Pick<ProbeTarget, 'methods' | 'access'>): string | null {
  if (t.methods.includes('GET')) return 'GET'
  if (t.methods.includes('HEAD')) return 'HEAD'
  return t.access.kind === 'public' ? null : t.methods[0] ?? null
}

export const probeUrl = (host: string, path: string) => `https://${host}${examplePath(path)}`

/** A redirect a gateway sends to sign in (login-ui, Kratos self-service, or another host's login). */
const toSignIn = (location: string | null) => !!location && /login|sign-?in|self-service|\/auth\b|return_to/i.test(location)

export function judge(expect: Expectation, status: number, location: string | null): Pick<ProbeResult, 'verdict' | 'level' | 'message'> {
  const two = status >= 200 && status < 300
  if (expect === 'public') {
    if (status >= 200 && status < 400) return { verdict: 'ok', level: 'ok', message: `public: answered ${status}` }
    if (status === 401 || status === 403) return { verdict: 'unexpected', level: 'warn', message: `declared public but refused anonymously (${status}): check the gate lets anonymous callers in` }
    if (status === 404) return { verdict: 'unexpected', level: 'warn', message: 'declared public but answered 404: no gateway rule (not loaded yet?) or the service has no such path' }
    return { verdict: 'unexpected', level: 'warn', message: `declared public but answered ${status}` }
  }
  if (two) return { verdict: 'exposed', level: 'error', message: `${expect === 'denied' ? 'denied' : 'protected'} route answered ${status} to an anonymous request: it is reachable without signing in` }
  if (status === 401 || status === 403) return { verdict: 'ok', level: 'ok', message: `refused anonymously (${status})` }
  if (status >= 300 && status < 400 && (expect === 'denied' || toSignIn(location))) return { verdict: 'ok', level: 'ok', message: `sent to sign in (${status})` }
  if (status === 404 && expect === 'denied') return { verdict: 'ok', level: 'ok', message: 'refused (404)' }
  if (status === 404) return { verdict: 'unexpected', level: 'warn', message: 'answered 404: no gateway rule matched (rules not loaded yet?)' }
  if (status >= 300 && status < 400) return { verdict: 'unexpected', level: 'warn', message: `redirected (${status}) to ${location ?? 'nowhere'}, not to sign in` }
  return { verdict: 'unexpected', level: 'warn', message: `answered ${status}` }
}

const networkError = (err: unknown) => {
  const e = err as { name?: string; code?: string; cause?: { code?: string }; message?: string }
  return e.cause?.code ?? e.code ?? (e.name === 'TimeoutError' ? 'timeout' : e.name) ?? 'error'
}

/** One anonymous request per route, one after another. The first network failure stops the probe. */
export async function probeRoutes(host: string, targets: readonly ProbeTarget[], budgetMs = PROBE_BUDGET_MS, clock: () => number = Date.now): Promise<ProbeReport> {
  const results: ProbeResult[] = []
  const probed = targets.slice(0, PROBE_MAX_ROUTES)
  const deadline = clock() + budgetMs
  for (const [i, t] of probed.entries()) {
    if (clock() + PROBE_TIMEOUT_MS > deadline) {
      return { available: true, results, notProbed: targets.slice(i).map((x) => x.route), stoppedBy: 'budget' }
    }
    const expect = expectationOf(t.access)
    const url = probeUrl(host, t.path)
    const method = probeMethod(t)
    if (!method) {
      results.push({ route: t.route, method: t.methods[0], url, expect, status: null, verdict: 'skipped', level: 'ok', message: 'public route that only writes: not probed, so nothing is written (use the curl command)' })
      continue
    }
    try {
      const res = await transport.request(method, url)
      results.push({ route: t.route, method, url, expect, status: res.status, ...(res.location ? { location: res.location } : {}), ...judge(expect, res.status, res.location) })
    } catch (err) {
      const why = networkError(err)
      // Nothing answered at all: jinbe has no way out (egress) or the host does not resolve here.
      if (results.every((r) => r.verdict === 'skipped')) {
        return { available: false, reason: `probe unavailable: jinbe could not reach ${url} (${why}); run the curl commands from a machine that can`, results: [], notProbed: targets.map((x) => x.route) }
      }
      results.push({ route: t.route, method, url, expect, status: null, verdict: 'unreachable', level: 'warn', message: `no answer (${why})` })
    }
  }
  return { available: true, results, notProbed: targets.slice(PROBE_MAX_ROUTES).map((t) => t.route) }
}

export interface WafReport { checked: boolean; blocked: boolean | null; status: number | null; url: string; message: string }

/**
 * One request carrying an attack-like query (a script tag, harmless to any service) that the WAF must
 * refuse with 403. One only: CrowdSec bans an address that trips the WAF repeatedly.
 */
export async function wafCheck(site: Pick<Site, 'address'>): Promise<WafReport> {
  const url = `https://${site.address.host}${site.address.pathPrefix ?? ''}/?jinbe_verify=${encodeURIComponent('<script>alert(1)</script>')}`
  try {
    const res = await transport.request('GET', url)
    return res.status === 403
      ? { checked: true, blocked: true, status: 403, url, message: 'the WAF refused an attack-like request (403)' }
      : { checked: true, blocked: false, status: res.status, url, message: `an attack-like request was answered ${res.status}: the WAF did not block it` }
  } catch (err) {
    return { checked: false, blocked: null, status: null, url, message: `WAF check unavailable: no answer (${networkError(err)})` }
  }
}

/** Ready-to-run commands for a route: anonymous, and with a bearer token placeholder. */
export function curlFor(host: string, t: Pick<ProbeTarget, 'route' | 'methods' | 'path'>) {
  const method = t.methods.includes('GET') ? 'GET' : t.methods[0]
  const url = probeUrl(host, t.path)
  const base = `curl -sS -o /dev/null -w '%{http_code}\\n'${method === 'GET' ? '' : ` -X ${method}`} '${url}'`
  return { route: t.route, method, url, anonymous: base, withToken: `${base} -H "Authorization: Bearer $TOKEN"` }
}
