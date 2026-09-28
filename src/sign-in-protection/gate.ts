import { createHash } from 'crypto'
import { env } from '../config/index.js'
import { getRedisClient } from '../services/redis-client.service.js'
import { signInGateDecisions } from '../telemetry/metrics.js'
import { verifyCaptcha } from './captcha.js'
import { captchaVerdict, registrationVerdict } from './guard.js'
import { getSignInProtection, type CaptchaFlow, type SignInProtection } from './settings.js'
import { rememberVerified } from './verified-tokens.js'

/**
 * The sign-in gate: judges a Kratos self-service submit BEFORE Kratos acts on it.
 *
 * Kratos emails a code or link the moment an address is submitted (code sign-in, code sign-up,
 * recovery, verification) and no Kratos hook runs at that moment, so the guard hook (guard.ts) comes
 * too late to stop an email flood. The bootstrap rules (build-rules.ts, SIGN_IN_GATE_ENABLED) send
 * every POST /self-service/{login,registration,recovery,verification} on the sign-in domain through
 * jinbe (gate-routes.ts), which reads the form, judges it here, and passes it on to Kratos or answers
 * itself. A script calling Kratos' API directly meets the same gate: there is no other public way in.
 *
 * Only a code-sending submit is judged. It must carry a bot-check token (X-Captcha-Token) when that
 * flow asks for the check, checked with the provider now — the one use the provider allows, so one
 * solved check sends one email — and it counts against the per-address and per-IP code limits. The
 * token is then remembered as verified so the guard hook accepts it once (verified-tokens.ts). A code
 * sign-up must also be one the registration policy allows, so no code goes to a refused address. Every
 * other submit (a code entered, a password, a profile step, a social sign-in) goes on unjudged; the
 * guard hook still checks sign-in and sign-up completions.
 */

export type GateStep = 'send' | 'other'

export type GateRefusal =
  | 'captcha_missing' | 'captcha_invalid' | 'captcha_unavailable' | 'rate_limited' | 'settings_unavailable'
  | 'registration_closed' | 'registration_not_allowed' | 'registration_disposable'

export type GateDecision =
  | { allow: true; step: GateStep; result: 'passed' | 'allowed' | 'fail_open' | 'not_guarded' | 'session' }
  | { allow: false; step: GateStep; result: GateRefusal; status: 403 | 429 | 503; message: string; retryAfter?: number }

export const GATE_FLOWS: readonly CaptchaFlow[] = ['login', 'registration', 'recovery', 'verification']

/** Methods whose submit never makes Kratos send an email. */
const NO_EMAIL_METHODS = new Set(['password', 'profile', 'oidc', 'saml', 'webauthn', 'passkey', 'totp', 'lookup_secret'])

type Fields = Record<string, unknown>

/** A form field, from a flat form body (`traits.email`) or a nested JSON one (`{traits: {email}}`). */
function field(fields: Fields, name: string): string | null {
  let v: unknown = fields[name]
  if (v === undefined && name.includes('.')) {
    v = name.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Fields)[k] : undefined), fields)
  }
  if (Array.isArray(v)) v = v[0]
  return typeof v === 'string' ? v : typeof v === 'number' ? String(v) : null
}

/** The address a submit is about, for the per-address limit: login's identifier, sign-up's email. */
const ADDRESS_FIELD: Record<CaptchaFlow, string> = {
  login: 'identifier',
  registration: 'traits.email',
  recovery: 'email',
  verification: 'email',
}

/**
 * What a submit is. `send`: Kratos will email a code or link — a code or link method with no code
 * typed, any resend, and login's identifier-first step (which emails the code when it is the only
 * method). A submit whose method cannot be read counts as `send`: the gate errs toward judging.
 */
export function classifySubmit(flow: CaptchaFlow, fields: Fields): { step: GateStep; address: string | null } {
  const address = field(fields, ADDRESS_FIELD[flow])?.trim().toLowerCase() || null
  const method = field(fields, 'method')
  const code = field(fields, 'code')
  if (field(fields, 'resend')) return { step: 'send', address }
  if (code) return { step: 'other', address }
  if (method && NO_EMAIL_METHODS.has(method)) return { step: 'other', address }
  return { step: 'send', address }
}

/** A submitted form body as fields; anything unreadable is no fields (and so a `send`). */
export function parseSubmitBody(contentType: string | undefined, body: Buffer): Fields {
  const type = (contentType ?? '').split(';')[0].trim().toLowerCase()
  const text = body.toString('utf8')
  try {
    if (type === 'application/json') {
      const v = JSON.parse(text)
      return v && typeof v === 'object' && !Array.isArray(v) ? (v as Fields) : {}
    }
    if (type === 'application/x-www-form-urlencoded') {
      const out: Fields = {}
      for (const [k, v] of new URLSearchParams(text)) if (!(k in out)) out[k] = v
      return out
    }
  } catch {
    // Unreadable: judged as a code-sending submit.
  }
  return {}
}

/**
 * The visitor's address as the edge saw it. Envoy overwrites x-envoy-external-address on every
 * external request and appends the peer to X-Forwarded-For, so the last X-Forwarded-For entry is
 * next best; the first entry is whatever the client wrote and is never used.
 */
export function gatewayClientIp(headers: Record<string, string | string[] | undefined>, fallback: string | null): string | null {
  const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[v.length - 1] : v)
  const edge = one(headers['x-envoy-external-address'])?.trim()
  if (edge) return edge
  const xff = one(headers['x-forwarded-for'])?.split(',').map((s) => s.trim()).filter(Boolean)
  return xff?.length ? xff[xff.length - 1] : fallback
}

export const hashForLog = (v: string) => createHash('sha256').update(v).digest('hex').slice(0, 16)

async function bounded<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([p, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms) })])
  } finally {
    clearTimeout(timer)
  }
}

/** One fixed-window counter; null when Redis cannot say (the limit is then skipped). */
async function countHit(key: string): Promise<{ count: number; ttl: number } | null> {
  try {
    const redis = getRedisClient()
    const count = await bounded(redis.incr(key), 500)
    if (count === 1) await bounded(redis.expire(key, env.SIGN_IN_GATE_WINDOW_S), 500)
    const ttl = await bounded(redis.ttl(key), 500)
    return { count, ttl: ttl > 0 ? ttl : env.SIGN_IN_GATE_WINDOW_S }
  } catch {
    return null
  }
}

/**
 * The per-address and per-IP code limits. Counted only for submits that passed the bot check, so a
 * script without tokens cannot use up somebody else's address budget.
 */
async function rateLimited(address: string | null, ip: string | null): Promise<{ retryAfter: number; by: 'address' | 'ip' } | null> {
  const checks: Array<[string, number, 'address' | 'ip']> = []
  if (address) checks.push([`sip:gate:addr:${createHash('sha256').update(address).digest('hex')}`, env.SIGN_IN_GATE_CODES_PER_ADDRESS, 'address'])
  if (ip) checks.push([`sip:gate:ip:${createHash('sha256').update(ip).digest('hex')}`, env.SIGN_IN_GATE_CODES_PER_IP, 'ip'])
  let over: { retryAfter: number; by: 'address' | 'ip' } | null = null
  for (const [key, limit, by] of checks) {
    const hit = await countHit(key)
    if (hit && hit.count > limit && (!over || hit.ttl > over.retryAfter)) over = { retryAfter: hit.ttl, by }
  }
  return over
}

function minutes(seconds: number): string {
  const m = Math.max(1, Math.ceil(seconds / 60))
  return m === 1 ? 'a minute' : `${m} minutes`
}

export interface GateInput {
  flow: CaptchaFlow
  fields: Fields
  token: string | null
  ip: string | null
  /** Whether the submit comes with a live Kratos session (a second factor, a refresh): asked lazily. */
  hasSession: () => Promise<boolean>
}

async function decide(input: GateInput, fetchImpl?: typeof fetch): Promise<GateDecision> {
  const { step, address } = classifySubmit(input.flow, input.fields)
  if (step !== 'send') return { allow: true, step, result: 'passed' }

  let settings: SignInProtection | null = null
  try {
    settings = await getSignInProtection()
  } catch {
    // Settings unreadable (guard.ts does the same): sign-up waits, the other flows go on.
    if (input.flow === 'registration') {
      return { allow: false, step, result: 'settings_unavailable', status: 503, message: 'Sign-up is unavailable right now. Please try again in a minute.' }
    }
  }

  let result: 'allowed' | 'fail_open' | 'not_guarded' | 'session' = 'not_guarded'
  if (settings?.captcha.flows[input.flow]) {
    if (await input.hasSession()) {
      // A signed-in person asking for a code to their own address (second factor, re-authentication).
      result = 'session'
    } else {
      const verdict = captchaVerdict(await verifyCaptcha(input.token, { action: input.flow, remoteIp: input.ip }, fetchImpl), settings.captcha.failMode)
      if (verdict && !verdict.allow) {
        return { allow: false, step, result: verdict.result as GateRefusal, status: 403, message: verdict.message.text }
      }
      result = verdict?.result === 'fail_open' ? 'fail_open' : 'allowed'
      if (result === 'allowed' && input.token) await rememberVerified(input.token, input.flow)
    }
  }

  // A sign-up the policy refuses is refused here too, before Kratos emails a code to that address
  // (the guard hook would refuse it only once the code came back).
  if (input.flow === 'registration' && settings) {
    const verdict = registrationVerdict(address, settings.registration)
    if (verdict && !verdict.allow) return { allow: false, step, result: verdict.result as GateRefusal, status: 403, message: verdict.message.text }
  }

  const limited = await rateLimited(address, input.ip)
  if (limited) {
    const message = limited.by === 'address'
      ? `Too many codes were sent to this address. Please wait ${minutes(limited.retryAfter)} and try again.`
      : `Too many codes were requested from your network. Please wait ${minutes(limited.retryAfter)} and try again.`
    return { allow: false, step, result: 'rate_limited', status: 429, message, retryAfter: limited.retryAfter }
  }
  return { allow: true, step, result }
}

/** Judges one self-service submit and counts the outcome. */
export async function gateSubmit(input: GateInput, fetchImpl?: typeof fetch): Promise<GateDecision> {
  const decision = await decide(input, fetchImpl)
  signInGateDecisions.inc({ flow: input.flow, step: decision.step, result: decision.result })
  return decision
}

/** The refusal body: the shape of a Kratos error, so a client that knows one reads this one. */
export function gateRefusalBody(decision: GateDecision & { allow: false }) {
  const status = decision.status === 429 ? 'Too Many Requests' : decision.status === 503 ? 'Service Unavailable' : 'Forbidden'
  return {
    error: {
      id: decision.result,
      code: decision.status,
      status,
      reason: decision.message,
      message: decision.message,
      ...(decision.retryAfter !== undefined ? { retry_after: decision.retryAfter } : {}),
    },
  }
}
