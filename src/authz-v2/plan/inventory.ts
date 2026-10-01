import type { GroupDefinition, RouteRule } from '../../services/redis-rbac.repository.js'
import type { IdentityFacts } from '../dataset.js'

/**
 * The v1 live state, as the plan reads it (authz-v2-design §3.3, wave V0). Read-only, with jinbe's own
 * credentials, inside the jinbe pod: Redis (every v1 RBAC key), Kratos (who is in what), the
 * organisation registry, Hydra (every OAuth client and its scopes). Nothing is written.
 */

export interface OAuthClientFacts {
  clientId: string
  /** `personal` (a person's key), `org` (an org's key), `other` (MCP or a registered client). */
  kind: 'personal' | 'org' | 'other'
  /** The org of an org key, the subject of a personal key. */
  owner: string | null
  name: string | null
  scopes: string[]
}

export interface V1Inventory {
  services: string[]
  /** svc → role → permissions (`global` included). */
  roles: Record<string, Record<string, string[]>>
  /** svc → rows. */
  routeMaps: Record<string, RouteRule[]>
  groups: Record<string, GroupDefinition>
  /** Groups flagged system in rbac:groups:meta. */
  systemGroups: string[]
  /** org → admin addresses (rbac:org_admins). */
  orgAdmins: Record<string, string[]>
  /** org → services (rbac:org_service_map). */
  orgServices: Record<string, string[]>
  /** org → address → groups (rbac:org_grants). */
  orgGrants: Record<string, Record<string, string[]>>
  /** Custom (non built-in) Oathkeeper rule ids in rbac:oathkeeper:rules. */
  oathkeeperRuleIds: string[]
  /** The bootstrap marker, as stored (schema, gitSha). */
  marker: { schemaVersion?: number; gitSha?: string } | null
  identities: Map<string, IdentityFacts & { id: string | null }>
  organisations: string[]
  clients: OAuthClientFacts[] | null
  /** What could not be read, so the review says so instead of reading as empty. */
  unavailable: string[]
}
