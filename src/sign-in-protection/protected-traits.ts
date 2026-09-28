import { isDeepStrictEqual } from 'util'
import { env } from '../config/index.js'

/**
 * Protected identity traits: values the gateway forwards to apps as trusted headers
 * (x-person-uuid ← traits.person_uuid, x-applicant-uuid ← traits.applicant_uuid), so a person must
 * never set them on themselves. Kratos has no read-only trait, and it renders every trait in the
 * schema as a sign-up and profile field; the guard web_hook is what stops them.
 *
 * WHAT THE HOOK CAN DO (verified in the Kratos v26.2.0 source, selfservice/hook/web_hook.go):
 *   - registration `after.<method>` and settings `after.profile` web_hooks with `response.parse: true`
 *     run BEFORE the identity is written (ExecutePostRegistrationPrePersistHook,
 *     ExecuteSettingsPrePersistHook). Only the method lists run there: the global `after.hooks` do not.
 *   - a 4xx with `messages` refuses the submit with a form message;
 *   - a 200 with `{"identity": {"traits": {...}}}` REPLACES the traits Kratos is about to write
 *     (whole object, parseWebhookResponse); Kratos then validates them against the schema.
 *   - the settings hook context carries both the traits being saved (`ctx.identity.traits`) and the
 *     ones stored now (`ctx.session.identity.traits`: the profile strategy updates a copy).
 * Only the profile method writes traits in settings; every registration method does (password,
 * code, oidc, webauthn, passkey), so each enabled one needs the guard in its own list.
 *
 * So:
 *   - sign-up: a protected trait with a value is refused; an empty one ("" from an older form) is
 *     dropped from the traits written.
 *   - profile: a protected trait sent with a different value is refused; one left out or emptied
 *     is put back to what is stored (a form that does not show it cannot wipe it).
 * The durable fix moves these values out of traits (metadata_admin) — scratchpad/research/protected-traits.md.
 */

export type Traits = Record<string, unknown>

export function protectedTraits(): string[] {
  return env.PROTECTED_TRAITS
}

const isTraits = (v: unknown): v is Traits => v !== null && typeof v === 'object' && !Array.isArray(v)
const blank = (v: unknown) => v === undefined || v === null || v === ''

export type TraitsVerdict =
  | { ok: true; traits?: Traits }
  | { ok: false; reason: 'protected_trait'; keys: string[] }
  | { ok: false; reason: 'unchecked' }

/** A sign-up's traits. `traits` on an ok verdict = what Kratos should write instead. */
export function registrationTraitsVerdict(submitted: unknown, names: readonly string[] = protectedTraits()): TraitsVerdict {
  if (!names.length) return { ok: true }
  if (!isTraits(submitted)) return { ok: false, reason: 'unchecked' }
  const present = names.filter((n) => n in submitted)
  const set = present.filter((n) => !blank(submitted[n]))
  if (set.length) return { ok: false, reason: 'protected_trait', keys: set }
  if (!present.length) return { ok: true }
  const traits = { ...submitted }
  for (const n of present) delete traits[n]
  return { ok: true, traits }
}

/** A profile save: `submitted` is what Kratos is about to write, `stored` what the identity has now. */
export function settingsTraitsVerdict(submitted: unknown, stored: unknown, names: readonly string[] = protectedTraits()): TraitsVerdict {
  if (!names.length) return { ok: true }
  if (!isTraits(submitted) || !isTraits(stored)) return { ok: false, reason: 'unchecked' }
  const changed = names.filter((n) => !blank(submitted[n]) && !isDeepStrictEqual(submitted[n], stored[n]))
  if (changed.length) return { ok: false, reason: 'protected_trait', keys: changed }
  const dropped = names.filter((n) => blank(submitted[n]) && !blank(stored[n]))
  const emptied = names.filter((n) => n in submitted && blank(submitted[n]) && blank(stored[n]))
  if (!dropped.length && !emptied.length) return { ok: true }
  const traits = { ...submitted }
  for (const n of dropped) traits[n] = stored[n]
  for (const n of emptied) delete traits[n]
  return { ok: true, traits }
}
