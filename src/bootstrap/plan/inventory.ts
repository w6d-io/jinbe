import type { GroupDefinition, RouteRule } from '../../services/redis-rbac.repository.js'
import type { OrgAssignments } from '../../services/org-roles.repository.js'

/**
 * The live RBAC state as the plan reads it (authz-v2-design §3.3, wave V0) — whatever release wrote
 * it: the previous model's keys (global roles, the org roster, org grants, the org → service map) are
 * read raw, so the plan works on an install that has not been migrated yet. Read-only, with jinbe's
 * own credentials, inside the jinbe pod: Redis, Kratos, the organisation registry, Hydra, the sites.
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

export interface IdentityInventory {
  id: string | null
  groups: string[]
  /** Every org the person belongs to (primary included). */
  organizations: string[]
  /** metadata_admin.organization_roles as stored — the previous model's org roles on the identity. */
  organizationRoles: Record<string, string[]>
}

/** One applied site's definitions, as its intent renders them. */
export interface SiteModel {
  roles: Record<string, string[]>
  routeMap: RouteRule[]
  /** platform group → this site's roles in it. */
  groups: Record<string, string[]>
  orgRoles: Record<string, string[]>
  everyOrg: Record<string, string[]>
  /** The orgs the intent entitles. */
  orgs: string[]
}

export interface Inventory {
  services: string[]
  /** svc → role → permissions (`global` included when an earlier release wrote it). */
  roles: Record<string, Record<string, string[]>>
  /** svc → rows. */
  routeMaps: Record<string, RouteRule[]>
  groups: Record<string, GroupDefinition>
  /** Groups flagged system in rbac:groups:meta. */
  systemGroups: string[]
  /** Previous model, read raw: org → admin addresses (rbac:org_admins). */
  orgAdmins: Record<string, string[]>
  /** Previous model, read raw: org → services (rbac:org_service_map). */
  orgServices: Record<string, string[]>
  /** Previous model, read raw: org → address → groups (rbac:org_grants). */
  orgGrants: Record<string, Record<string, string[]>>
  /** org → sites entitled (rbac:org_sites). */
  orgSites: Record<string, string[]>
  /** svc → org roles; svc → every-org map (rbac:org_roles:*, rbac:every_org:*). */
  orgRoles: Record<string, Record<string, string[]>>
  everyOrg: Record<string, Record<string, string[]>>
  /** org → identity id → org roles (rbac:org_assignments). */
  orgAssignments: OrgAssignments
  /** The applied sites (their permissions are republished from their intents). */
  sites: string[]
  /**
   * What each applied site's applied version renders to — exactly what the reseed writes (wildcards
   * made explicit, org-grantable entries as org roles). Sites that could not be rendered are in
   * `siteFailures`, and the apply leaves them unpublished.
   */
  siteModels: Record<string, SiteModel>
  siteFailures: Array<{ site: string; error: string }>
  /** Custom (non built-in) Oathkeeper rule ids in rbac:oathkeeper:rules. */
  oathkeeperRuleIds: string[]
  /** The bootstrap marker, as stored (schema, gitSha). */
  marker: { schemaVersion?: number; gitSha?: string } | null
  identities: Map<string, IdentityInventory>
  organisations: string[]
  clients: OAuthClientFacts[] | null
  /** What could not be read, so the review says so instead of reading as empty. */
  unavailable: string[]
}
