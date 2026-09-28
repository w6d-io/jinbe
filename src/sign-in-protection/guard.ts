import { signInGuardDecisions } from '../telemetry/metrics.js'
import { verifyCaptcha, type VerifyResult } from './captcha.js'
import { domainAndParents, isDisposable } from './disposable.js'
import { getSignInProtection, type CaptchaFlow, type SignInProtection } from './settings.js'

/**
 * The server-side half of sign-in protection: what the interrupting Kratos web_hook asks
 * (POST /api/webhooks/kratos/guard) before a sign-up is stored or a sign-in gets its session.
 *
 * WHAT KRATOS CAN INTERRUPT (verified in the v26.2.0 source, selfservice/hook/web_hook.go):
 *   - registration `after.<method>` with `response.parse: true` (or `can_interrupt`) runs BEFORE the
 *     identity is persisted; a 4xx with a `messages` body becomes a form error. Method-level only:
 *     the global `after.hooks` list never runs pre-persist.
 *   - login `after` with `can_interrupt: true` runs before the session cookie is issued — but only
 *     once the password was accepted (see the login note below).
 *   - recovery and verification have NO hook at the moment a code or link is sent: `before` runs at
 *     flow creation (no answer yet), `after` once the code was used. Their bot check is enforced at
 *     the gateway instead (POST /api/public/sign-in-protection/check, from an Oathkeeper remote_json
 *     authorizer).
 *
 * The hook fires for API flows too (/self-service/registration/api), which is the point: a script
 * that never loads login-ui still meets this check.
 *
 * Login note: Kratos runs login `after` hooks only on a correct password, so a script that skips the
 * bot check learns whether a password is right (bot-check refusal vs "credentials invalid"), though it
 * never gets a session. The login check stops automated sign-ins, not password guessing — that needs
 * the gateway rate limit.
 */

export type Refusal =
  | 'captcha_missing'
  | 'captcha_invalid'
  | 'captcha_unavailable'
  | 'registration_closed'
  | 'registration_not_allowed'
  | 'registration_disposable'
  | 'settings_unavailable'

export type Decision =
  | { allow: true; result: 'allowed' | 'fail_open' | 'not_guarded' }
  | { allow: false; result: Refusal; message: KratosText }

export interface KratosText {
  id: number
  text: string
  /**
   * Where Kratos shows it. Always `#/`, the form-level message: on the two-step sign-up (details, then
   * password) the email field is hidden on the step this hook answers, so a message under it is lost.
   */
  pointer: string
}

/** Message ids in Kratos' validation range, so login-ui can recognise them without matching text. */
export const GUARD_MESSAGE_IDS = {
  captcha_missing: 4000901,
  captcha_invalid: 4000902,
  captcha_unavailable: 4000903,
  registration_closed: 4000911,
  registration_not_allowed: 4000912,
  registration_disposable: 4000913,
  settings_unavailable: 4000914,
} as const satisfies Record<Refusal, number>

function refuse(result: Refusal, text: string): Decision {
  return { allow: false, result, message: { id: GUARD_MESSAGE_IDS[result], text, pointer: '#/' } }
}

/** The 4xx body Kratos turns into a form message (web_hook.go parseWebhookResponse). */
export function kratosRefusalBody(message: KratosText) {
  return {
    messages: [{ instance_ptr: message.pointer, messages: [{ id: message.id, text: message.text, type: 'error' }] }],
  }
}

const matchesDomain = (domain: string, entry: string): boolean =>
  entry.startsWith('*.') ? domain.endsWith(entry.slice(1)) : domain === entry

function limitedToText(domains: string[]): string {
  const shown = domains.filter((d) => !d.startsWith('*.')).slice(0, 5)
  if (!shown.length) return 'Sign-ups are limited to invited addresses. Ask an administrator for an account.'
  const more = domains.length > shown.length ? ' and a few others' : ''
  return `Sign-ups are limited to ${shown.map((d) => `@${d}`).join(', ')} addresses${more}.`
}

/** The registration policy alone, for one address. null = may sign up. */
export function registrationVerdict(email: string | null | undefined, policy: SignInProtection['registration']): Decision | null {
  if (policy.mode === 'closed') {
    return refuse('registration_closed', 'Sign-ups are closed. Ask an administrator to create your account.')
  }
  const address = (email ?? '').trim().toLowerCase()
  const at = address.lastIndexOf('@')
  const domain = at > 0 ? address.slice(at + 1) : ''
  const listed = !!domain && (policy.allowEmails.includes(address) || policy.allowDomains.some((e) => matchesDomain(domain, e)))

  // An address an administrator listed by name or domain is theirs to allow, disposable or not.
  if (!listed && domain) {
    const denied = policy.denyDomains.some((e) => domainAndParents(domain).some((d) => matchesDomain(d, e)))
    if (denied || (policy.blockDisposable && isDisposable(domain))) {
      return refuse('registration_disposable', 'This email provider cannot be used to sign up. Use your work or personal address.')
    }
  }
  if (policy.mode === 'allowlist' && !listed) {
    return refuse('registration_not_allowed', limitedToText(policy.allowDomains))
  }
  return null
}

function captchaVerdict(result: VerifyResult, failMode: SignInProtection['captcha']['failMode']): Decision | null {
  if (result.ok) return null
  switch (result.reason) {
    case 'missing':
      return refuse('captcha_missing', 'Please complete the bot check, then try again.')
    case 'invalid':
      return refuse('captcha_invalid', 'The bot check did not pass or has expired. Please complete it again.')
    default:
      // The check could not be made (provider down, or not configured on this service).
      if (failMode === 'open') return { allow: true, result: 'fail_open' }
      return refuse('captcha_unavailable', 'The bot check is unavailable right now. Please try again in a minute.')
  }
}

export interface GuardInput {
  flow: CaptchaFlow
  /** Kratos flow type: `browser` or `api`. */
  flowType?: string | null
  /** The credential the submit used (`password`, `code`, `totp`, `oidc`…). */
  method?: string | null
  requestedAal?: string | null
  email?: string | null
  captchaToken?: string | null
  ip?: string | null
}

/** Methods whose sign-in proves the first factor, and so gets the bot check. */
const FIRST_FACTOR = new Set(['password', 'code', 'identifier_first'])

async function decide(input: GuardInput, fetchImpl?: typeof fetch): Promise<Decision> {
  let settings: SignInProtection
  try {
    settings = await getSignInProtection()
  } catch {
    // Redis unreadable and nothing cached. Sign-up waits; sign-in, recovery and verification go on,
    // so an outage of the settings store never locks every administrator out.
    if (input.flow === 'registration') return refuse('settings_unavailable', 'Sign-up is unavailable right now. Please try again in a minute.')
    return { allow: true, result: 'fail_open' }
  }

  if (input.flow === 'registration' && settings.registration.mode === 'closed') {
    return registrationVerdict(input.email, settings.registration) as Decision
  }

  let guarded = settings.captcha.flows[input.flow]
  // A second factor, and an IdP-vouched sign-up, are not where bots get in.
  if (input.flow === 'login' && (input.requestedAal === 'aal2' || (input.method && !FIRST_FACTOR.has(input.method)))) guarded = false
  if (input.flow === 'registration' && input.method === 'oidc') guarded = false
  let failOpen = false
  if (guarded) {
    const verdict = captchaVerdict(await verifyCaptcha(input.captchaToken, { action: input.flow, remoteIp: input.ip }, fetchImpl), settings.captcha.failMode)
    if (verdict && !verdict.allow) return verdict
    failOpen = verdict?.result === 'fail_open'
  }

  if (input.flow === 'registration') {
    const verdict = registrationVerdict(input.email, settings.registration)
    if (verdict) return verdict
  }
  if (failOpen) return { allow: true, result: 'fail_open' }
  return { allow: true, result: guarded || input.flow === 'registration' ? 'allowed' : 'not_guarded' }
}

/** Judges one guarded submit and counts the outcome. */
export async function guardFlow(input: GuardInput, fetchImpl?: typeof fetch): Promise<Decision> {
  const decision = await decide(input, fetchImpl)
  signInGuardDecisions.inc({ flow: input.flow, result: decision.result })
  return decision
}
