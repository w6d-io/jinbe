import { CATALOG, PERMISSIONS, effectivePermissions, specOf, type Permission } from '../policy/catalog.js'
import { ROLES, STAFF_ROLES } from '../policy/roles.js'
import { STEP_UP_MAX_AGE_MS, secondFactorIsFresh, type StepUpState } from '../services/step-up.js'
import { KEY_STEP_UP_MAX_AGE_MS, KEY_STEP_UP_PERMISSIONS } from '../middleware/delegated-step-up.js'
import type { MfaMethod } from '../services/kratos.service.js'
import { declaredRoute } from '../policy/declared-routes.js'
import type { Site } from '../sites/schemas.js'
import { secondFactorGaps, twoFactorOn } from '../sites/render.js'
import type { GroupFlag } from './settings.js'
import { getMcpSettings } from '../mcp/settings.js'

/**
 * Every rule that asks for a second factor, said in one place so the console and the MCP can show
 * it next to what it applies to (a group badge, a permission, a site, a refusal). DESCRIPTIVE ONLY:
 * the rules are enforced where they always were — OPA (rbac.rego § 8b per-site, § 8c groups), the
 * catalogue step-up (requireRecentMfa), the target-enrolment check (user-groups.service) and the
 * personal-key stand-in (delegated-step-up.ts). Nothing here decides a request.
 *
 *   group_sign_in        a group's "Members must use 2FA" switch (settings.ts): its members need an
 *                        aal2 session on every route that carries a permission, on every app
 *   step_up              a catalogue permission marked stepUp needs a second factor proven within
 *                        15 minutes (fourEyes is shown beside it: a second person in prod)
 *   enrol_before_joining the same per-group switch: nobody is added to a group that requires 2FA
 *                        before they have enrolled a second factor
 *   site_login           a site's own bar (login.twoFactor): all / writes / routes / none
 *   personal_key         a personal MCP key stands in for the step-up of a few permissions with the
 *                        factor proven at its creation, for 30 days
 *   oauth_grant          an OAuth grant stands in the same way, for the same permissions, with the
 *                        factor proven at consent, when the user allowed protected actions there —
 *                        for the MCP setting oauth.protectedActionsHours (default 12), capped at the grant end
 * No organisation-level rule exists: an organisation cannot ask its members for a second factor.
 */

export type SecondFactorRule = 'group_sign_in' | 'step_up' | 'enrol_before_joining' | 'site_login' | 'personal_key' | 'oauth_grant'

export const STEP_UP_MAX_AGE_MIN = STEP_UP_MAX_AGE_MS / 60_000
export const PERSONAL_KEY_MAX_AGE_DAYS = KEY_STEP_UP_MAX_AGE_MS / 86_400_000
/** The fallback when the MCP settings cannot be read (oauthGrantWindowHours reads the live window). */
export const OAUTH_GRANT_MAX_AGE_HOURS = 12
export const OAUTH_GRANT_SETTING = 'mcp.oauth.protectedActionsHours'

export const RULES: ReadonlyArray<{ id: SecondFactorRule; label: string; status: 'enforced' | 'planned' }> = [
  { id: 'group_sign_in', label: "A group's \"Members must use 2FA\" switch: its members must use two-step sign-in (aal2) on every permission-carrying route", status: 'enforced' },
  { id: 'step_up', label: `These permissions need a second factor proven within the last ${STEP_UP_MAX_AGE_MIN} minutes`, status: 'enforced' },
  { id: 'enrol_before_joining', label: 'The same switch: nobody is added to such a group before they have enrolled a second factor', status: 'enforced' },
  { id: 'site_login', label: "A site's own two-step sign-in bar: every request, changes only, chosen routes, or none", status: 'enforced' },
  { id: 'personal_key', label: `A personal AI key stands in for the step-up of a few permissions with the second factor proven when it was created, for ${PERSONAL_KEY_MAX_AGE_DAYS} days`, status: 'enforced' },
  { id: 'oauth_grant', label: `An OAuth grant stands in the same way, with the second factor proven at consent when the user allowed protected actions, for ${OAUTH_GRANT_MAX_AGE_HOURS} hours by default (MCP setting)`, status: 'enforced' },
]

// ── groups ────────────────────────────────────────────────────

export interface GroupSecondFactor {
  /** The group's "Members must use 2FA" switch: members sign in at aal2, and must enrol before joining. */
  required: boolean
  /** group_setting: stored (a super admin, the boot migration, or the legacy list); default: not stored yet, computed from the roles. */
  source: 'group_setting' | 'default'
  /** Same switch, rule (b): nobody is added before they have enrolled. Always equal to `required`. */
  enrolBeforeJoining: boolean
  /** What the default would be (on for a group that can change anything or holds `*`). */
  defaultRequired: boolean
}

export function groupSecondFactor(flag: GroupFlag | undefined): GroupSecondFactor {
  const required = flag?.required ?? false
  return { required, source: flag?.explicit ? 'group_setting' : 'default', enrolBeforeJoining: required, defaultRequired: flag?.default ?? false }
}

// ── permissions ───────────────────────────────────────────────

export interface StepUpRule {
  required: boolean
  /** How recent the second factor must be; null when none is asked. */
  maxAgeMin: number | null
  /** A personal key may stand in, with the factor proven at its creation (personal_key); null when it may not. */
  viaPersonalKey: { maxAgeDays: number } | null
  /** An OAuth grant may stand in, with the factor proven at consent, when the user opted in there; null when it may not. */
  viaOAuthGrant: { maxAgeHours: number; setting: string; requiresConsentOptIn: true } | null
  /** A second person in prod (change request). */
  fourEyes: 'prod' | false
}

/**
 * The OAuth protected-actions window as the administrator set it (Settings → AI assistants): hours, or
 * null when OAuth grants may not stand in at all (protectedActions 'off'). The default when the settings
 * cannot be read.
 */
export async function oauthGrantWindowHours(): Promise<number | null> {
  try {
    const { oauth } = await getMcpSettings()
    return oauth.protectedActions === 'off' ? null : oauth.protectedActionsHours
  } catch {
    return OAUTH_GRANT_MAX_AGE_HOURS
  }
}

export function stepUpRule(permission: string, oauthHours: number | null = OAUTH_GRANT_MAX_AGE_HOURS): StepUpRule | null {
  const spec = specOf(permission)
  if (!spec) return null
  const keyStandsIn = spec.stepUp && KEY_STEP_UP_PERMISSIONS.has(permission) && spec.delegable === 'direct'
  return {
    required: spec.stepUp,
    maxAgeMin: spec.stepUp ? STEP_UP_MAX_AGE_MIN : null,
    viaPersonalKey: keyStandsIn ? { maxAgeDays: PERSONAL_KEY_MAX_AGE_DAYS } : null,
    // Same permissions as a personal key (delegatedStepUpVerdict).
    viaOAuthGrant: keyStandsIn && oauthHours !== null ? { maxAgeHours: oauthHours, setting: OAUTH_GRANT_SETTING, requiresConsentOptIn: true } : null,
    fourEyes: spec.fourEyes,
  }
}

/** The catalogue permissions these held names amount to that need a recent second factor. */
export function stepUpPermissionsOf(held: readonly string[]): Permission[] {
  return effectivePermissions(held).filter((p) => CATALOG[p].stepUp)
}

export const permissionRules = (oauthHours: number | null = OAUTH_GRANT_MAX_AGE_HOURS) =>
  PERMISSIONS.map((name) => ({ name, label: CATALOG[name].label, stepUpRule: stepUpRule(name, oauthHours)! }))

export const roleRules = () =>
  STAFF_ROLES.map((name) => ({ name, group: ROLES[name].group, stepUpPermissions: stepUpPermissionsOf(ROLES[name].permissions) }))

// ── sites ─────────────────────────────────────────────────────

export interface SiteSecondFactor {
  scope: 'none' | 'writes' | 'all' | 'routes'
  /** Route ids that ask for it whatever the scope. */
  routes: string[]
  /** OAuth clients: let through, or refused (a token carries no sign-in level). Null when the site asks nothing. */
  clients: 'exempt' | 'refused' | null
  /** What is enforced: aal1 when the site asks nothing, or when a gate it needs never asks the policy. */
  minAal: 'aal1' | 'aal2'
  /** Whether the gates make the policy check it: null when the site asks nothing (or its gates were not given). */
  enforced: boolean | null
  /** Gates covering routes the 2FA applies to that never ask the policy (so nobody checks it there). */
  notEnforcedOn: string[]
  /** The same, in one sentence for a person. */
  summary: string
}

/** Pass the gates and routes too (a whole site) to know whether the gates enforce what login asks. */
export function siteSecondFactor(site: Pick<Site, 'login'> & Partial<Pick<Site, 'gates' | 'routes'>>): SiteSecondFactor {
  const tf = site.login?.twoFactor
  const on = twoFactorOn(site)
  const routes = tf?.routes ?? []
  const scope = tf?.scope ?? 'none'
  const also = routes.length > 0 ? ` and on ${routes.length} chosen route${routes.length === 1 ? '' : 's'}` : ''
  let summary: string
  if (!on) summary = 'This site asks for no two-step sign-in (the platform groups rule still applies).'
  else if (scope === 'all') summary = 'Two-step sign-in on every signed-in request.'
  else if (scope === 'writes') summary = `Two-step sign-in for changes (POST, PUT, PATCH, DELETE)${also}; reading works after a password.`
  else summary = `Two-step sign-in on ${routes.length} chosen route${routes.length === 1 ? '' : 's'} only.`
  if (on && tf?.clients === 'refused') summary += ' OAuth clients are refused where it applies.'
  const gaps = on && site.gates && site.routes ? secondFactorGaps({ login: site.login, gates: site.gates, routes: site.routes }).map((g) => g.gate) : []
  const enforced = on && site.gates && site.routes ? gaps.length === 0 : null
  if (enforced === false) {
    summary = `Two-step sign-in is set but NOT enforced: gate${gaps.length === 1 ? '' : 's'} ${gaps.map((g) => `'${g}'`).join(', ')} never ask${gaps.length === 1 ? 's' : ''} the policy, so any account passes there without it. (Set: ${summary})`
  }
  return { scope, routes: [...routes], clients: on ? (tf?.clients ?? null) : null, minAal: on && enforced !== false ? 'aal2' : 'aal1', enforced, notEnforcedOn: gaps, summary }
}

// ── one person ────────────────────────────────────────────────

/** The groups switched on (settings.ts getSecondFactorSetting). */
export interface SignInSetting {
  groups: readonly string[]
  explicit: boolean
}

export interface UserSecondFactor {
  /** Must sign in at aal2 (group_sign_in). */
  required: boolean
  /** The groups that make it required. */
  requiredBecause: string[]
  /** Has enrolled a second factor; null when it could not be read. */
  enrolled: boolean | null
  methods: MfaMethod[] | null
  /** The caller's own session level; null when describing somebody else (no one session to read). */
  currentAal: string | null
  /** Minutes since the second factor was proven in this session; null when unknown or never. */
  factorAgeMin: number | null
  /** Whether a step-up permission would pass right now; null when describing somebody else. */
  stepUpFresh: boolean | null
  /** Their permissions that need a recent second factor; null when their permissions could not be read. */
  stepUpPermissions: Permission[] | null
}

export function userSecondFactor(input: {
  groups: readonly string[]
  permissions: readonly string[] | null
  setting: SignInSetting
  methods: MfaMethod[] | null
  session?: StepUpState | null
  now?: number
}): UserSecondFactor {
  const now = input.now ?? Date.now()
  const requiredBecause = input.groups.filter((g) => input.setting.groups.includes(g)).sort()
  const s = input.session
  const at = s?.secondFactorAt ? new Date(s.secondFactorAt).getTime() : NaN
  const aal2 = s?.aal === 'aal2'
  return {
    required: requiredBecause.length > 0,
    requiredBecause,
    enrolled: input.methods ? input.methods.length > 0 : aal2 ? true : null,
    methods: input.methods,
    currentAal: s ? (s.aal ?? null) : null,
    factorAgeMin: s && aal2 && Number.isFinite(at) ? Math.max(0, Math.floor((now - at) / 60_000)) : null,
    stepUpFresh: s ? secondFactorIsFresh(s, now) : null,
    stepUpPermissions: input.permissions ? stepUpPermissionsOf(input.permissions) : null,
  }
}

// ── refusals ──────────────────────────────────────────────────

/** The permission the route table declares for this request's route, or null. */
export function routePermissionOf(request: { method?: string; routeOptions?: { url?: string } }): string | null {
  if (!request.method || !request.routeOptions?.url) return null
  return declaredRoute(request.method, request.routeOptions.url)?.permission ?? null
}

/**
 * What a 2FA refusal adds beside its `error`: which rule fired and what satisfies it, in the
 * permission-refusal shape (`permission`, `hint`) kuma and auth-mcp already render.
 */
export function secondFactorRefusal(rule: SecondFactorRule, extra: {
  permission?: string | null
  requiredBecause?: readonly string[]
  groups?: readonly string[]
  keyReason?: string
} = {}): Record<string, unknown> {
  return {
    ...(extra.permission ? { permission: extra.permission } : {}),
    secondFactor: {
      rule,
      requiredAal: 'aal2',
      ...(rule === 'step_up' ? { maxAgeMin: STEP_UP_MAX_AGE_MIN } : {}),
      ...(extra.requiredBecause ? { requiredBecause: [...extra.requiredBecause] } : {}),
      ...(extra.groups ? { groups: [...extra.groups] } : {}),
      ...(extra.keyReason ? { keyReason: extra.keyReason } : {}),
    },
  }
}
