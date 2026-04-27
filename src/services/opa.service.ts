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
}

export const opaService = new OpaService()

// Backward compat export
export const opalService = opaService
