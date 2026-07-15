import { env } from '../config/index.js'

/**
 * User RBAC information from OPA
 */
export interface UserRbacInfo {
  email: string
  groups: string[]
  roles: string[]
  permissions: string[]
}

/**
 * OPA query response
 */
interface OpaUserInfoResponse {
  result?: {
    email: string
    groups: string[]
    roles: string[]
    permissions: string[]
  }
}

/**
 * Matching route_map rule (subset returned by simulate)
 */
export interface SimulateMatchingRule {
  method: string
  path: string
  permission?: string
}

/**
 * Output of `data.rbac.simulate` rego rule.
 *
 * Single round-trip permission preview: returns the live `allow` decision
 * plus the diagnostic context needed to render a faithful trace
 * (matching rules, user's resolved groups/roles/permissions, super-admin
 * flag). Used by /api/admin/rbac/simulate.
 */
export interface SimulateResult {
  allow: boolean
  matching_rules: SimulateMatchingRule[]
  groups: string[]
  roles: string[]
  permissions: string[]
  super_admin: boolean
}

interface OpaSimulateResponse {
  result?: SimulateResult
}

/**
 * OPA Service
 * Queries OPA for user RBAC information via /v1/data/rbac/user_info
 */
class OpaService {
  private baseUrl: string

  constructor() {
    this.baseUrl = env.OPA_URL
  }

  async getUserInfo(email: string, app: string): Promise<UserRbacInfo | null> {
    try {
      const response = await fetch(`${this.baseUrl}/v1/data/rbac/user_info`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: { email, app } }),
      })

      if (!response.ok) return null

      const data = (await response.json()) as OpaUserInfoResponse

      if (!data.result) return null

      return {
        email: data.result.email,
        groups: data.result.groups || [],
        roles: data.result.roles || [],
        permissions: data.result.permissions || [],
      }
    } catch (error) {
      console.error(`[opa] user_info query failed:`, error)
      return null
    }
  }

  /**
   * Run a single-query permission preview against the live OPA instance.
   * Returns null if OPA is unreachable or returns a non-2xx response — the
   * caller should treat this as an infrastructure error, not "deny".
   */
  async simulate(
    email: string,
    app: string,
    action: string,
    object: string,
  ): Promise<SimulateResult | null> {
    try {
      const response = await fetch(`${this.baseUrl}/v1/data/rbac/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: { email, app, action, object } }),
      })

      if (!response.ok) return null

      const data = (await response.json()) as OpaSimulateResponse

      if (!data.result) return null

      return {
        allow: !!data.result.allow,
        matching_rules: data.result.matching_rules || [],
        groups: data.result.groups || [],
        roles: data.result.roles || [],
        permissions: data.result.permissions || [],
        super_admin: !!data.result.super_admin,
      }
    } catch (error) {
      console.error(`[opa] simulate query failed:`, error)
      return null
    }
  }
  /**
   * Delegation grant decision — "may the actor grant target_group to a user in
   * target_org?" Queries data.rbac.delegation.can_grant (the containment policy).
   * The rego resolves the actor's permissions from OPA data by email, so we send
   * ONLY the email (never a caller-supplied permission set).
   *
   * FAIL-CLOSED: unlike getUserInfo/simulate (which return null on infra error),
   * this returns `false` on any error / non-2xx / missing result — an unreachable
   * or erroring OPA must never allow a privilege-changing grant.
   */
  async canGrant(input: {
    actor: { email: string }
    target_group: string
    target_org: string
  }): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/v1/data/rbac/delegation/can_grant`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input }),
      })
      if (!response.ok) return false
      const data = (await response.json()) as { result?: boolean }
      return data.result === true
    } catch (error) {
      console.error(`[opa] can_grant query failed (deny):`, error)
      return false
    }
  }

  /**
   * Orgs the actor administers — `data.rbac.delegation.manageable_orgs`. The
   * rego resolves membership + org-admin authority from OPAL data by email, so
   * we send ONLY the email. Returns the org-id set as an array.
   *
   * FAIL-CLOSED: returns `[]` on any error / non-2xx / non-array result — an
   * unreachable OPA must scope the actor to nothing, never grant reach.
   */
  async manageableOrgs(email: string): Promise<string[]> {
    return this.delegationSet('manageable_orgs', email)
  }

  /**
   * Groups the actor may assign — `data.rbac.delegation.assignable_groups`
   * (single-service, containment-bounded, never global). Email-only input;
   * FAIL-CLOSED to `[]`. Callers scope the result to a specific org's service.
   */
  async assignableGroups(email: string): Promise<string[]> {
    return this.delegationSet('assignable_groups', email)
  }

  /**
   * Shared helper for the delegation set-valued rules (manageable_orgs /
   * assignable_groups). OPA serialises a rego set as a JSON array. Fail-closed:
   * any error / non-2xx / non-array result yields `[]`.
   */
  private async delegationSet(rule: string, email: string): Promise<string[]> {
    try {
      const response = await fetch(`${this.baseUrl}/v1/data/rbac/delegation/${rule}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: { actor: { email } } }),
      })
      if (!response.ok) return []
      const data = (await response.json()) as { result?: unknown }
      return Array.isArray(data.result) ? (data.result as string[]) : []
    } catch (error) {
      console.error(`[opa] ${rule} query failed (empty):`, error)
      return []
    }
  }
}

export const opaService = new OpaService()

// Backward compat export
export const opalService = opaService
