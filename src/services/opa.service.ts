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
}

export const opaService = new OpaService()

// Backward compat export
export const opalService = opaService
