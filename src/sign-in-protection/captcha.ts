import { env } from '../config/index.js'

/**
 * The bot-check provider: login-ui renders its widget, this service checks the answer.
 *
 * Cloudflare Turnstile first; hCaptcha and reCAPTCHA v3 speak the same siteverify dialect (form POST
 * of secret + response + remoteip → JSON with `success`), so they differ only in URL, script and the
 * extra checks their answer allows (action, score). The secret comes from the environment
 * (Vault-injected) and is sent to the provider only.
 *
 * Every provider's published test keys are recognised: they always answer the same thing, so a
 * production deployment carrying one would have no bot check at all. They count as "not configured"
 * in production unless CAPTCHA_ALLOW_TEST_KEYS says otherwise (a sandbox that wants them).
 */

export type ProviderId = 'turnstile' | 'hcaptcha' | 'recaptcha'

export type VerifyFailure = 'missing' | 'invalid' | 'unavailable' | 'not_configured'
export type VerifyResult = { ok: true } | { ok: false; reason: VerifyFailure; codes?: string[] }

interface ProviderSpec {
  verifyUrl: string
  scriptUrl: string
  /** Secrets that always answer the same thing, whatever the token. */
  testSecrets: readonly string[]
  /** Whether the answer carries the widget's `action`, so a token solved for sign-in cannot sign up. */
  checksAction: boolean
}

export const PROVIDERS: Record<ProviderId, ProviderSpec> = {
  turnstile: {
    verifyUrl: 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    scriptUrl: 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit',
    // Always passes · always fails · "token already spent".
    testSecrets: ['1x0000000000000000000000000000000AA', '2x0000000000000000000000000000000AA', '3x0000000000000000000000000000000AA'],
    checksAction: true,
  },
  hcaptcha: {
    verifyUrl: 'https://api.hcaptcha.com/siteverify',
    scriptUrl: 'https://js.hcaptcha.com/1/api.js?render=explicit',
    testSecrets: ['0x0000000000000000000000000000000000000000'],
    checksAction: false,
  },
  recaptcha: {
    verifyUrl: 'https://www.google.com/recaptcha/api/siteverify',
    scriptUrl: 'https://www.google.com/recaptcha/api.js?render=explicit',
    testSecrets: ['6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'],
    checksAction: true,
  },
}

export interface ProviderStatus {
  provider: ProviderId
  /** Site key, secret and (in production) a real key pair: the check can be made. */
  configured: boolean
  siteKey: string | null
  scriptUrl: string
  secretSet: boolean
  testKeys: boolean
  /** Why it is not configured, in words for the console. */
  problem: string | null
}

export function providerStatus(): ProviderStatus {
  const provider = env.CAPTCHA_PROVIDER
  const spec = PROVIDERS[provider]
  const siteKey = env.CAPTCHA_SITE_KEY ?? null
  const secret = env.CAPTCHA_SECRET_KEY
  const testKeys = !!secret && spec.testSecrets.includes(secret)
  let problem: string | null = null
  if (!siteKey) problem = 'CAPTCHA_SITE_KEY is not set'
  else if (!secret) problem = 'CAPTCHA_SECRET_KEY is not set'
  else if (testKeys && env.NODE_ENV === 'production' && !env.CAPTCHA_ALLOW_TEST_KEYS) {
    problem = "the provider's test keys are refused in production (they pass every visitor)"
  }
  return { provider, configured: !problem, siteKey, scriptUrl: spec.scriptUrl, secretSet: !!secret, testKeys, problem }
}

interface SiteverifyAnswer {
  success?: boolean
  'error-codes'?: string[]
  hostname?: string
  action?: string
  score?: number
}

/** Provider error codes that mean "the visitor's answer is bad", as opposed to "we could not ask". */
const BAD_ANSWER = /missing-input-response|invalid-input-response|timeout-or-duplicate|bad-request/

/**
 * Checks one token. `action` is the flow the widget was rendered for: a token solved on the
 * sign-in page is not an answer for sign-up. Never throws; an unreachable or confused provider is
 * `unavailable`, and the caller decides with the fail mode.
 */
export async function verifyCaptcha(
  token: string | null | undefined,
  expect: { action: string; remoteIp?: string | null },
  fetchImpl: typeof fetch = fetch,
): Promise<VerifyResult> {
  const status = providerStatus()
  if (!status.configured) return { ok: false, reason: 'not_configured' }
  if (!token || typeof token !== 'string') return { ok: false, reason: 'missing' }
  if (token.length > 4096) return { ok: false, reason: 'invalid' }

  const spec = PROVIDERS[status.provider]
  const form = new URLSearchParams({ secret: env.CAPTCHA_SECRET_KEY as string, response: token })
  if (expect.remoteIp) form.set('remoteip', expect.remoteIp)

  let answer: SiteverifyAnswer
  try {
    const res = await fetchImpl(spec.verifyUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
      signal: AbortSignal.timeout(env.CAPTCHA_VERIFY_TIMEOUT_MS),
    })
    if (!res.ok) return { ok: false, reason: 'unavailable', codes: [`http_${res.status}`] }
    answer = (await res.json()) as SiteverifyAnswer
  } catch {
    return { ok: false, reason: 'unavailable' }
  }

  const codes = answer['error-codes'] ?? []
  if (answer.success !== true) {
    // A provider that refuses OUR request (bad secret, internal error) is not the visitor's fault.
    if (codes.length && !codes.some((c) => BAD_ANSWER.test(c))) return { ok: false, reason: 'unavailable', codes }
    return { ok: false, reason: 'invalid', codes }
  }
  // Test keys answer with placeholder hostnames and no action: only the success bit means anything.
  if (status.testKeys) return { ok: true }
  const hosts = env.CAPTCHA_EXPECTED_HOSTNAMES
  if (hosts.length && !hosts.includes((answer.hostname ?? '').toLowerCase())) {
    return { ok: false, reason: 'invalid', codes: ['hostname-mismatch'] }
  }
  if (spec.checksAction && answer.action !== undefined && answer.action !== '' && answer.action !== expect.action) {
    return { ok: false, reason: 'invalid', codes: ['action-mismatch'] }
  }
  if (status.provider === 'recaptcha' && (answer.score ?? 0) < env.CAPTCHA_RECAPTCHA_MIN_SCORE) {
    return { ok: false, reason: 'invalid', codes: ['score-too-low'] }
  }
  return { ok: true }
}
