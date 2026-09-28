import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { providerStatus } from './captcha.js'

/**
 * The platform setting "how the public sign-in flows are protected" — rbac:config
 * `sign_in_protection`, one JSON document edited from the console (Settings → Sign-in protection).
 *
 *   captcha.flows          which Kratos flows ask for the bot check (guard.ts enforces it)
 *   captcha.failMode       what happens when the check cannot be made (provider down or not
 *                          configured): `closed` refuses, `open` lets the attempt through
 *   registration.mode      `open` anyone · `allowlist` only listed emails/domains · `closed` nobody
 *                          (an administrator creates accounts)
 *   registration.*         the allow-list, the extra deny-list, and the built-in disposable list
 *
 * Unset: open sign-up, and the bot check on every flow as soon as a provider is configured (a flow
 * left out of the stored document follows the same default; one stored `false` stays off). Read by the Kratos web_hook on every
 * guarded submit, so it is cached for a few seconds; a write refreshes the cache at once.
 */

export const SIGN_IN_PROTECTION_KEY = 'sign_in_protection'

export const CAPTCHA_FLOWS = ['registration', 'login', 'recovery', 'verification'] as const
export type CaptchaFlow = (typeof CAPTCHA_FLOWS)[number]
export const REGISTRATION_MODES = ['open', 'allowlist', 'closed'] as const
export type RegistrationMode = (typeof REGISTRATION_MODES)[number]
export const FAIL_MODES = ['closed', 'open'] as const
export type FailMode = (typeof FAIL_MODES)[number]

export interface SignInProtection {
  captcha: { flows: Record<CaptchaFlow, boolean>; failMode: FailMode }
  registration: {
    mode: RegistrationMode
    allowEmails: string[]
    allowDomains: string[]
    denyDomains: string[]
    blockDisposable: boolean
  }
}

export const MAX_LIST = 500
export const EMAIL = /^[a-z0-9._%+'-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/
/** `example.com`, or `*.example.com` for every subdomain (not the apex). */
export const DOMAIN = /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/

export function defaultSignInProtection(): SignInProtection {
  const on = providerStatus().configured
  return {
    captcha: { flows: { registration: on, login: on, recovery: on, verification: on }, failMode: 'closed' },
    registration: { mode: 'open', allowEmails: [], allowDomains: [], denyDomains: [], blockDisposable: false },
  }
}

export type SettingsProblem = { field: string; message: string }

const cleanList = (v: string[]): string[] => [...new Set(v.map((s) => s.trim().toLowerCase()).filter(Boolean))].sort()

/**
 * A candidate document as a clean one, or the problems that stop it. Lists are trimmed,
 * lowercased, de-duplicated and sorted, so the stored value and the audit diff are canonical.
 */
export function validateSignInProtection(input: unknown, opts: { forSave?: boolean } = { forSave: true }): { ok: true; value: SignInProtection } | { ok: false; problems: SettingsProblem[] } {
  const problems: SettingsProblem[] = []
  const o = (input ?? {}) as Record<string, unknown>
  const c = (o.captcha ?? {}) as Record<string, unknown>
  const r = (o.registration ?? {}) as Record<string, unknown>
  const flowsIn = (c.flows ?? {}) as Record<string, unknown>
  const value = defaultSignInProtection()

  for (const f of CAPTCHA_FLOWS) {
    if (flowsIn[f] === undefined) continue
    if (typeof flowsIn[f] !== 'boolean') problems.push({ field: `captcha.flows.${f}`, message: 'must be true or false' })
    else value.captcha.flows[f] = flowsIn[f] as boolean
  }
  if (c.failMode !== undefined) {
    if (!FAIL_MODES.includes(c.failMode as FailMode)) problems.push({ field: 'captcha.failMode', message: 'must be closed or open' })
    else value.captcha.failMode = c.failMode as FailMode
  }
  if (r.mode !== undefined) {
    if (!REGISTRATION_MODES.includes(r.mode as RegistrationMode)) problems.push({ field: 'registration.mode', message: 'must be open, allowlist or closed' })
    else value.registration.mode = r.mode as RegistrationMode
  }
  if (r.blockDisposable !== undefined) {
    if (typeof r.blockDisposable !== 'boolean') problems.push({ field: 'registration.blockDisposable', message: 'must be true or false' })
    else value.registration.blockDisposable = r.blockDisposable
  }
  const lists: Array<[keyof SignInProtection['registration'] & ('allowEmails' | 'allowDomains' | 'denyDomains'), RegExp, string]> = [
    ['allowEmails', EMAIL, 'not an email address'],
    ['allowDomains', DOMAIN, 'not a domain (example.com or *.example.com)'],
    ['denyDomains', DOMAIN, 'not a domain (example.com or *.example.com)'],
  ]
  for (const [key, re, what] of lists) {
    const raw = r[key]
    if (raw === undefined) continue
    if (!Array.isArray(raw) || !raw.every((s) => typeof s === 'string')) {
      problems.push({ field: `registration.${key}`, message: 'must be a list of strings' })
      continue
    }
    const list = cleanList(raw as string[])
    if (list.length > MAX_LIST) problems.push({ field: `registration.${key}`, message: `at most ${MAX_LIST} entries` })
    const bad = list.filter((s) => s.length > 254 || !re.test(s))
    if (bad.length) problems.push({ field: `registration.${key}`, message: `${what}: ${bad.slice(0, 5).join(', ')}` })
    value.registration[key] = list
  }
  if (opts.forSave && value.registration.mode === 'allowlist' && !value.registration.allowEmails.length && !value.registration.allowDomains.length) {
    problems.push({ field: 'registration.allowDomains', message: 'an allow-list needs at least one email or domain (or choose closed)' })
  }
  return problems.length ? { ok: false, problems } : { ok: true, value }
}

/** A stored value as a clean document; a missing or unreadable one is the default (open sign-up, check on when configured). */
export function parseSignInProtection(raw: string | undefined): SignInProtection {
  if (raw === undefined) return defaultSignInProtection()
  try {
    // Only this service writes the key, through the validator. An empty allow-list read back is
    // honoured as written (nobody may sign up) rather than refused; anything unreadable is the default.
    const v = validateSignInProtection(JSON.parse(raw), { forSave: false })
    return v.ok ? v.value : defaultSignInProtection()
  } catch {
    return defaultSignInProtection()
  }
}

const TTL_MS = 5_000
let cached: { at: number; value: SignInProtection } | null = null

/** Test seam. */
export function resetSignInProtectionCache(): void {
  cached = null
}

/**
 * The current document. Throws when Redis cannot be read and nothing was ever read; after one good
 * read a Redis outage keeps answering the last known document (stale beats guessing, both ways).
 */
export async function getSignInProtection(): Promise<SignInProtection> {
  if (cached && Date.now() - cached.at < TTL_MS) return cached.value
  try {
    const config = await redisRbacRepository.getConfig()
    const value = parseSignInProtection(config[SIGN_IN_PROTECTION_KEY])
    cached = { at: Date.now(), value }
    return value
  } catch (err) {
    if (cached) return cached.value
    throw err
  }
}

export async function setSignInProtection(value: SignInProtection): Promise<SignInProtection> {
  await redisRbacRepository.setConfig(SIGN_IN_PROTECTION_KEY, JSON.stringify(value))
  cached = { at: Date.now(), value }
  return value
}
