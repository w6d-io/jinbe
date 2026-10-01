import { OpaQueryError, OpaUnavailableError, opaConfigured, queryOpa } from './opa-client.js'

/**
 * "Can this person do METHOD PATH, and why?" — asked of the engine that decides it.
 *
 * Nothing here re-implements the policy: the verdict is `data.rbac.decision` (what the gateway
 * enforces), and the explanation is `data.rbac.simulate` for the service that owns the route. A
 * JS-side replay would drift from the rego the first time either changed.
 */

export type AccessCheckInput = {
  email: string
  method: string
  path: string
  /** Pin the service instead of letting the policy resolve the route's owner. */
  app?: string
  /**
   * The sign-in level to judge the request at, as the person would browse: `aal1` after a password,
   * `aal2` after a second factor. Unset, OPA is asked with no level at all (below aal1).
   */
  aal?: 'aal1' | 'aal2'
}

/**
 * Only on `needs_2fa`: the request fails on the sign-in level alone. `allowedAtAal2` is OPA asked
 * again at aal2; `requiredBy` says who demands the second factor — the site (per-site 2FA,
 * data.site_login) and/or a platform group the person is in (data.second_factor).
 */
export type StepUp = {
  requiredAal: 'aal2'
  allowedAtAal2: boolean
  requiredBy: Array<'site' | 'platform_group'>
}

export type AccessCheckResult = {
  allow: boolean
  /** `ok` | `not_found` | `forbidden` | `forbidden_org`, as the gateway receives it. */
  reason: string
  /** The service whose rules decided, or null when no service owns the route (none, or a tie). */
  app: string | null
  /** Every service holding the best-ranked match. Two or more is a tie: the policy answers not_found. */
  owners: string[]
  matchingRules: Array<{ method: string; path: string; permission?: string }>
  groups: string[]
  roles: string[]
  permissions: string[]
  /** The level asked at, when one was given. */
  aal?: 'aal1' | 'aal2'
  stepUp?: StepUp
}

// Unconfigured (503) and unanswered (502), under the names the route has always caught.
export { OpaUnavailableError as AccessCheckUnavailableError, OpaQueryError }

type Decision = { allow?: boolean; reason?: string; groups?: string[] }
type Simulation = {
  matching_rules?: AccessCheckResult['matchingRules']
  roles?: string[]
  permissions?: string[]
}

export async function checkAccess(input: AccessCheckInput): Promise<AccessCheckResult> {
  if (!opaConfigured()) {
    throw new OpaUnavailableError(
      'Access check is not configured on this deployment: set OPA_URL and OPA_TOKEN (the OPA bearer token).',
    )
  }

  const query = <T>(rule: string, opaInput: Record<string, unknown>) => queryOpa<T>(`rbac/${rule}`, opaInput)

  const base = { email: input.email, action: input.method, object: input.path }
  const pinned = input.app ? { ...base, app: input.app } : base
  const asked = input.aal ? { ...pinned, aal: input.aal } : pinned

  // owning_apps is only computed when no app is pinned, so it is asked without one.
  const [decision, owningApps] = await Promise.all([
    query<Decision>('decision', asked),
    query<string[]>('owning_apps', base),
  ])
  if (!decision) throw new OpaQueryError('OPA has no rbac.decision — is the policy loaded?')

  const owners = [...(owningApps ?? [])].sort()
  const app = input.app ?? (owners.length === 1 ? owners[0] : null)
  const simulation = (await query<Simulation>('simulate', app ? { ...base, app } : base)) ?? {}
  const reason = decision.reason ?? (decision.allow ? 'ok' : 'forbidden')

  // needs_2fa means granted but for the sign-in level: say so, and whether aal2 would pass.
  let stepUp: StepUp | undefined
  if (reason === 'needs_2fa' && input.aal !== 'aal2') {
    const [atAal2, siteCfg, platform] = await Promise.all([
      query<Decision>('decision', { ...pinned, aal: 'aal2' }),
      query<{ min_aal?: unknown }>('site_login_cfg', app ? { ...base, app } : base),
      query<boolean>('second_factor_required', { email: input.email }),
    ])
    stepUp = {
      requiredAal: 'aal2',
      allowedAtAal2: atAal2?.allow === true,
      requiredBy: [...(siteCfg?.min_aal ? ['site' as const] : []), ...(platform === true ? ['platform_group' as const] : [])],
    }
  }

  return {
    allow: decision.allow === true,
    reason,
    app,
    owners,
    matchingRules: simulation.matching_rules ?? [],
    groups: decision.groups ?? [],
    roles: simulation.roles ?? [],
    permissions: simulation.permissions ?? [],
    ...(input.aal ? { aal: input.aal } : {}),
    ...(stepUp ? { stepUp } : {}),
  }
}
