import { isIP } from 'node:net'
import { env } from '../config/index.js'
import { getRedisClient } from '../services/redis-client.service.js'
import { hydraService } from '../services/hydra.service.js'
import { hydraFlows } from '../services/hydra-flows.service.js'
import { componentLogger } from '../telemetry/logger.js'
import { MCP_SCOPE, OFFLINE_SCOPE } from './metadata.js'

/**
 * The locked-down client registration for MCP clients (RFC 7591 subset), `POST /oauth2/register` on
 * the Hydra host. Hydra's own DCR stays off: it takes any redirect (https phishing targets), has no
 * brake, cannot force the audience or our metadata, and hands out a self-management token.
 *
 * Accepted (owner decisions 2026-09-30: loopback callbacks only, DCR through jinbe, no pre-registered
 * clients): 1–5 `http://localhost|127.0.0.1|[::1]:<port>/<path>` redirects (explicit port ≥ 1024, no
 * query, fragment or userinfo), a public client (`none`), the code and refresh grants. Everything else
 * is forced: the audience is the MCP resource alone, tokens are opaque, 15 min access / 7 day idle
 * refresh, and the client is bound to the first person who consents (consent.ts). Registration
 * answers no secret and no registration access token. Unconsented clients go after 1 h (gc.ts).
 */

export const DCR_OWNER = 'mcp-dcr'
export const MCP_CLIENT_KIND = 'mcp_oauth'
export const MAX_REDIRECTS = 5
export const MAX_SCOPES = 300
export const MAX_UNCONSENTED = 500
const NAME_MAX = 64
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]'])
const PERMISSION = /^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_-]*$/
const ACCESS_LIFESPAN = '15m'
const REFRESH_LIFESPAN = '168h'

export type RegistrationError = { status: 400 | 429 | 503; error: string; error_description: string; retryAfter?: number }

export interface ValidRegistration {
  client_name: string
  redirect_uris: string[]
  scopes: string[]
}

const bad = (error: string, error_description: string): RegistrationError => ({ status: 400, error, error_description })

/** One redirect URI, or why not. */
export function loopbackRedirect(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length > 256 || /[?#\s]/.test(raw)) return null
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return null
  }
  if (u.protocol !== 'http:' || u.username || u.password || !LOOPBACK.has(u.hostname)) return null
  // `new URL` drops a default port (:80), so an explicit, non-privileged one must survive parsing.
  const port = Number(u.port)
  if (!u.port || !Number.isInteger(port) || port < 1024 || port > 65535) return null
  return raw
}

/** The RFC 7591 body as the client we will create, or the 400 it earns. */
export function validateRegistration(body: unknown): ValidRegistration | RegistrationError {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return bad('invalid_client_metadata', 'The body must be a JSON object')
  const b = body as Record<string, unknown>

  const uris = b.redirect_uris
  if (!Array.isArray(uris) || uris.length < 1 || uris.length > MAX_REDIRECTS) {
    return bad('invalid_redirect_uri', `redirect_uris must list 1 to ${MAX_REDIRECTS} loopback addresses`)
  }
  const redirects = uris.map(loopbackRedirect)
  if (redirects.some((r) => r === null)) {
    return bad('invalid_redirect_uri', 'Only http://localhost, http://127.0.0.1 or http://[::1] with an explicit port (1024–65535), without query or fragment, are accepted')
  }

  if (b.token_endpoint_auth_method !== undefined && b.token_endpoint_auth_method !== 'none') {
    return bad('invalid_client_metadata', "token_endpoint_auth_method must be 'none' (public clients only)")
  }
  if (b.grant_types !== undefined) {
    if (!Array.isArray(b.grant_types) || !b.grant_types.every((g) => g === 'authorization_code' || g === 'refresh_token')) {
      return bad('invalid_client_metadata', 'grant_types may only be authorization_code and refresh_token')
    }
  }
  if (b.response_types !== undefined) {
    if (!Array.isArray(b.response_types) || b.response_types.length !== 1 || b.response_types[0] !== 'code') {
      return bad('invalid_client_metadata', "response_types must be ['code']")
    }
  }

  let name = 'MCP client'
  if (b.client_name !== undefined) {
    if (typeof b.client_name !== 'string') return bad('invalid_client_metadata', 'client_name must be a string')
    // Printable only: no control or format characters (bidi overrides) to disguise what is shown.
    const clean = b.client_name.replace(/[\p{Cc}\p{Cf}]/gu, '').replace(/\s+/g, ' ').trim().slice(0, NAME_MAX).trim()
    if (clean) name = clean
  }

  let scopes: string[] = []
  if (b.scope !== undefined) {
    if (typeof b.scope !== 'string') return bad('invalid_client_metadata', 'scope must be a space-separated string')
    const tokens = [...new Set(b.scope.split(' ').filter(Boolean))]
    if (tokens.length > MAX_SCOPES) return bad('invalid_client_metadata', `scope may name at most ${MAX_SCOPES} scopes`)
    scopes = tokens.filter((t) => t === MCP_SCOPE || t === OFFLINE_SCOPE || (t.length <= 128 && PERMISSION.test(t)))
  }
  for (const s of [MCP_SCOPE, OFFLINE_SCOPE]) if (!scopes.includes(s)) scopes.push(s)

  return { client_name: name, redirect_uris: redirects as string[], scopes }
}

/** The /24 (IPv4) or /48 (IPv6) a caller comes from: what the per-address brake and the audit record. */
export function ipNet(ip: string): string {
  const v4 = /^(?:::ffff:)?(\d+)\.(\d+)\.(\d+)\.\d+$/i.exec(ip)
  if (v4 && isIP(`${v4[1]}.${v4[2]}.${v4[3]}.0`) === 4) return `${v4[1]}.${v4[2]}.${v4[3]}.0/24`
  if (isIP(ip) === 6) {
    // Expand `::` so the first three groups are the real ones.
    const [head, tail = ''] = ip.split('::')
    const h = head ? head.split(':') : []
    const t = tail ? tail.split(':') : []
    const groups = ip.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h
    return `${groups.slice(0, 3).map((g) => g.toLowerCase().replace(/^0+(?=.)/, '')).join(':')}::/48`
  }
  return 'unknown'
}

/** MCP_OAUTH_DCR_RATE (`10/h/ip,200/d`); a malformed value keeps the defaults. */
export function dcrRate(raw: string = env.MCP_OAUTH_DCR_RATE): { perIpHour: number; perDay: number } {
  const m = /^\s*(\d+)\/h\/ip\s*,\s*(\d+)\/d\s*$/.exec(raw ?? '')
  const perIpHour = m ? Number(m[1]) : 10
  const perDay = m ? Number(m[2]) : 200
  return { perIpHour: perIpHour > 0 ? perIpHour : 10, perDay: perDay > 0 ? perDay : 200 }
}

async function count(key: string, windowS: number): Promise<{ n: number; ttl: number }> {
  const redis = getRedisClient()
  const n = await redis.incr(key)
  if (n === 1) await redis.expire(key, windowS)
  const ttl = n > 1 ? await redis.ttl(key) : windowS
  return { n, ttl: ttl > 0 ? ttl : windowS }
}

/**
 * The brake, per network and for everyone. Anonymous and unauthenticated, so it fails CLOSED: with
 * the counters unreachable nobody registers (503), rather than everybody without limit.
 */
export async function registrationBrake(net: string, now: number = Date.now()): Promise<RegistrationError | null> {
  const { perIpHour, perDay } = dcrRate()
  try {
    const ip = await count(`jinbe:oauth-dcr:ip:${net}`, 3600)
    if (ip.n > perIpHour) return { status: 429, error: 'rate_limited', error_description: 'Too many registrations from your network. Try again later.', retryAfter: ip.ttl }
    const day = await count(`jinbe:oauth-dcr:day:${new Date(now).toISOString().slice(0, 10)}`, 86_400)
    if (day.n > perDay) return { status: 429, error: 'rate_limited', error_description: 'Too many registrations today. Try again later.', retryAfter: day.ttl }
    return null
  } catch (err) {
    componentLogger('oauth').warn({ reason: (err as Error).message }, 'registration brake unavailable (refused)')
    return { status: 503, error: 'temporarily_unavailable', error_description: 'Registration is unavailable right now. Try again later.' }
  }
}

/** Registered MCP clients no one has consented to yet. */
export async function unconsentedClients(): Promise<number> {
  const clients = await hydraService.listAllClients(500, 2, DCR_OWNER)
  return clients.filter((c) => c.metadata?.kind === MCP_CLIENT_KIND && !c.metadata?.bound_subject).length
}

export interface RegisteredClient {
  client_id: string
  client_id_issued_at: number
  client_name: string
  redirect_uris: string[]
  grant_types: string[]
  response_types: string[]
  token_endpoint_auth_method: 'none'
  scope: string
}

/** Creates the Hydra client with every field forced. */
export async function createMcpClient(v: ValidRegistration, ctx: { net: string; ua: string | null; audience: string; now?: number }): Promise<RegisteredClient> {
  const now = ctx.now ?? Date.now()
  const body = {
    client_name: v.client_name,
    redirect_uris: v.redirect_uris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    audience: [ctx.audience],
    scope: v.scopes.join(' '),
    skip_consent: false,
    skip_logout_consent: false,
    owner: DCR_OWNER,
    access_token_strategy: 'opaque',
    authorization_code_grant_access_token_lifespan: ACCESS_LIFESPAN,
    authorization_code_grant_refresh_token_lifespan: REFRESH_LIFESPAN,
    refresh_token_grant_access_token_lifespan: ACCESS_LIFESPAN,
    refresh_token_grant_refresh_token_lifespan: REFRESH_LIFESPAN,
    metadata: {
      kind: MCP_CLIENT_KIND,
      registered_at: new Date(now).toISOString(),
      registered_ip_net: ctx.net,
      user_agent: (ctx.ua ?? '').slice(0, 200),
      bound_subject: null,
    },
  }
  const client = await hydraFlows.createClient(body)
  return {
    client_id: client.client_id,
    client_id_issued_at: Math.floor((client.created_at ? Date.parse(client.created_at) : now) / 1000),
    client_name: v.client_name,
    redirect_uris: v.redirect_uris,
    grant_types: body.grant_types,
    response_types: body.response_types,
    token_endpoint_auth_method: 'none',
    scope: body.scope,
  }
}
