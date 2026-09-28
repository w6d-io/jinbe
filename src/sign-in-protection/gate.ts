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
 * Kratos looks the address up (and answers "this account does not exist" to a code sign-in) and
 * emails a code or link the moment an address is submitted; no Kratos hook runs at that moment. The
 * bootstrap rules (build-rules.ts, SIGN_IN_GATE_ENABLED) send every POST
 * /self-service/{login,registration,recovery,verification,settings} on the sign-in domain through
 * jinbe (gate-routes.ts), which reads the form, judges it here, and passes it on to Kratos or answers
 * itself. A script calling Kratos' API directly (browser or API flows, any method) meets the same gate.
 *
 * For a flow whose bot check is on, EVERY submit needs a bot-check token (X-Captcha-Token):
 *   - a token checked with the provider now (spent: the provider allows one use), or
 *   - the pass that token earned on this flow (same Kratos flow id, ten minutes, a few uses): it
 *     covers the next steps about the SAME address (the code typed after it was sent, the code sent
 *     after the sign-up details) and at most one email. A new address, or a second email, needs a
 *     new solve — so no lookup and no email happens without a solved check.
 * The token is also left verified for the guard hook (verified-tokens.ts), which accepts it once.
 * Passkey submits are not judged (no lookup, no email; webauthn is). Settings: only a profile save that changes the email (Kratos checks it is free and emails a
 * verification) is judged, under the verification toggle. A login with a live session (second factor,
 * re-authentication, to the person's own address) needs no token.
 *
 * Code-sending submits also count against the per-address and per-IP limits, and a code sign-up must
 * be one the registration policy allows. Flows without the bot check only get those two.
 */

export type GateStep = 'send' | 'other'

export type GateRefusal =
  | 'captcha_missing' | 'captcha_invalid' | 'captcha_unavailable' | 'rate_limited' | 'settings_unavailable'
  | 'registration_closed' | 'registration_not_allowed' | 'registration_disposable'

export type GateFlow = CaptchaFlow | 'settings'

export type GateDecision =
  | { allow: true; step: GateStep; result: 'passed' | 'allowed' | 'flow_pass' | 'fail_open' | 'not_guarded' | 'session' }
  | { allow: false; step: GateStep; result: GateRefusal; status: 403 | 429 | 503; message: string; retryAfter?: number }

export const GATE_FLOWS: readonly GateFlow[] = ['login', 'registration', 'recovery', 'verification', 'settings']

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
const ADDRESS_FIELD: Record<GateFlow, string> = {
  login: 'identifier',
  registration: 'traits.email',
  recovery: 'email',
  verification: 'email',
  settings: 'traits.email',
}

/**
 * What a submit is. `send`: Kratos will email a code or link — a code or link method with no code
 * typed, any resend, and login's identifier-first step (which emails the code when it is the only
 * method). A submit whose method cannot be read counts as `send`: the gate errs toward judging.
 * Settings: a profile save that changes the email is the `send` (a verification email to it).
 */
export function classifySubmit(flow: GateFlow, fields: Fields, sessionEmail: string | null = null): { step: GateStep; address: string | null } {
  const address = field(fields, ADDRESS_FIELD[flow])?.trim().toLowerCase() || null
  const method = field(fields, 'method')
  if (flow === 'settings') {
    const changesEmail = method === 'profile' && !!address && address !== (sessionEmail ?? '').trim().toLowerCase()
    return { step: changesEmail ? 'send' : 'other', address: changesEmail ? address : null }
  }
  const code = field(fields, 'code')
  if (field(fields, 'resend')) return { step: 'send', address }
  if (code) return { step: 'other', address }
  if (method && NO_EMAIL_METHODS.has(method)) return { step: 'other', address }
  return { step: 'send', address }
}

/**
 * The bot-check token of a submit: the X-Captcha-Token header, or — for a native form post that cannot
 * set a header (Kratos' webauthn.js passkey submit) — the `transient_payload.captcha_token` field,
 * which the guard hook reads too.
 */
export function submitToken(header: string | null, fields: Fields): string | null {
  if (header) return header
  const v = field(fields, 'transient_payload.captcha_token')
  return v && v.length <= 4096 ? v : null
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

/**
 * The pass a solved check earns on one Kratos flow: the token's hash, the address it was solved for,
 * whether it already sent an email, and how often it was used. Redis down: no pass, every submit
 * needs a fresh solve.
 */
interface FlowPass { t: string; a: string | null; s: boolean; u: number }
const PASS_USES = 8
const passKey = (flowId: string) => `sip:gate:pass:${createHash('sha256').update(flowId).digest('hex')}`
const tokenHash = (token: string) => createHash('sha256').update(token).digest('hex')

async function readPass(flowId: string): Promise<FlowPass | null> {
  try {
    const raw = await bounded(getRedisClient().get(passKey(flowId)), 500)
    return raw ? (JSON.parse(raw) as FlowPass) : null
  } catch {
    return null
  }
}

async function writePass(flowId: string, pass: FlowPass): Promise<void> {
  try {
    await bounded(getRedisClient().set(passKey(flowId), JSON.stringify(pass), 'EX', env.SIGN_IN_GATE_VERIFIED_TTL_S), 500)
  } catch {
    // Without a pass the next step of this flow asks for a new solve.
  }
}

/** Whether this token's pass on this flow covers this submit (and uses it up by one). */
async function usePass(flowId: string | null, token: string | null, step: GateStep, address: string | null): Promise<boolean> {
  if (!flowId || !token) return false
  const pass = await readPass(flowId)
  if (!pass || pass.t !== tokenHash(token) || pass.u >= PASS_USES) return false
  if (address && address !== pass.a) return false
  if (step === 'send' && pass.s) return false
  await writePass(flowId, { ...pass, s: pass.s || step === 'send', u: pass.u + 1 })
  return true
}

export interface GateInput {
  flow: GateFlow
  /** The Kratos flow id (`?flow=`), which a pass is bound to. */
  flowId: string | null
  fields: Fields
  token: string | null
  ip: string | null
  /** The live Kratos session this submit carries, if any (asked lazily): its email, or null. */
  session: () => Promise<{ email: string | null } | null>
}

const refusal = (step: GateStep, result: GateRefusal, status: 403 | 429 | 503, message: string): GateDecision =>
  ({ allow: false, step, result, status, message })

async function decide(input: GateInput, fetchImpl?: typeof fetch): Promise<GateDecision> {
  let settings: SignInProtection | null = null
  try {
    settings = await getSignInProtection()
  } catch {
    // Settings unreadable (guard.ts does the same): sign-up waits, the other flows go on unchecked.
    if (input.flow === 'registration') return refusal('send', 'settings_unavailable', 503, 'Sign-up is unavailable right now. Please try again in a minute.')
  }

  const session = input.flow === 'settings' || input.flow === 'login' ? await input.session() : null
  const { step, address } = classifySubmit(input.flow, input.fields, session?.email ?? null)
  const toggle: CaptchaFlow = input.flow === 'settings' ? 'verification' : input.flow
  let guarded = !!settings?.captcha.flows[toggle]
  // Settings: only the email change is judged; any other save is the person's own business.
  if (input.flow === 'settings' && step !== 'send') guarded = false
  // A passkey submit (Kratos' webauthn.js posts a native form, no header) looks no address up — the
  // authenticator names the account — and sends no email. `webauthn` stays judged: Kratos v26 looks its
  // identifier up first and answers an unknown one differently (strategy/webauthn/login.go), so it
  // carries the token in transient_payload.captcha_token.
  if (field(input.fields, 'method') === 'passkey') guarded = false

  let result: 'passed' | 'allowed' | 'flow_pass' | 'fail_open' | 'not_guarded' | 'session' = step === 'send' ? 'not_guarded' : 'passed'
  if (guarded && settings) {
    if (input.flow === 'login' && session) {
      // A signed-in person: a second factor or a re-authentication, to their own address.
      result = 'session'
    } else if (await usePass(input.flowId, input.token, step, address)) {
      result = 'flow_pass'
    } else {
      const verdict = captchaVerdict(await verifyCaptcha(input.token, { action: toggle, remoteIp: input.ip }, fetchImpl), settings.captcha.failMode)
      if (verdict && !verdict.allow) return refusal(step, verdict.result as GateRefusal, 403, verdict.message.text)
      result = verdict?.result === 'fail_open' ? 'fail_open' : 'allowed'
      if (result === 'allowed' && input.token) {
        await rememberVerified(input.token, toggle)
        if (input.flowId) await writePass(input.flowId, { t: tokenHash(input.token), a: address, s: step === 'send', u: 0 })
      }
    }
  }
  if (step !== 'send') return { allow: true, step, result }

  // A sign-up the policy refuses is refused here too, before Kratos emails a code to that address
  // (the guard hook would refuse it only once the code came back).
  if (input.flow === 'registration' && settings) {
    const verdict = registrationVerdict(address, settings.registration)
    if (verdict && !verdict.allow) return refusal(step, verdict.result as GateRefusal, 403, verdict.message.text)
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
