import type { AdminState } from '../kratos.service.js'

/**
 * Membership as the identity carries it, and the only place its rules are written down:
 *
 *   organization_id                     the primary organisation (Kratos's own column)
 *   metadata_admin.organizations        every other one
 *   metadata_admin.organization_roles   {org: [role]} for anything beyond plain membership
 *
 * Pure functions over AdminState, applied by KratosService.updateAdminState under the identity's
 * lock, so the primary and the list always move in one write.
 */

export const MEMBER = 'member'

/** metadata_admin.organization_roles, keeping only well-formed entries. */
export function rolesByOrganisation(raw: unknown): Record<string, string[]> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
  const out: Record<string, string[]> = {}
  for (const [org, roles] of Object.entries(raw as Record<string, unknown>)) {
    if (!Array.isArray(roles)) continue
    const valid = roles.filter((r): r is string => typeof r === 'string' && r.length > 0)
    if (valid.length > 0) out[org] = valid
  }
  return out
}

function listed(state: AdminState): string[] {
  const raw = state.metadataAdmin.organizations
  return Array.isArray(raw) ? raw.filter((id): id is string => typeof id === 'string' && id.length > 0) : []
}

/** Every organisation the identity belongs to: the primary one, then the list. */
export function organisationsOn(state: AdminState): string[] {
  return [...new Set([...(state.organizationId ? [state.organizationId] : []), ...listed(state)])]
}

export function rolesIn(state: AdminState, organisationId: string): string[] {
  return rolesByOrganisation(state.metadataAdmin.organization_roles)[organisationId] ?? []
}

/** An emptied list stays an empty list; a list that never existed is not created empty. */
function withList(state: AdminState, list: string[]): AdminState {
  if (list.length === 0 && !('organizations' in state.metadataAdmin)) return state
  return { ...state, metadataAdmin: { ...state.metadataAdmin, organizations: list } }
}

function withRoles(state: AdminState, organisationId: string, roles: string[]): AdminState {
  const all = rolesByOrganisation(state.metadataAdmin.organization_roles)
  if (roles.length > 0) all[organisationId] = [...new Set(roles)].sort()
  else delete all[organisationId]
  const metadataAdmin = { ...state.metadataAdmin }
  if (Object.keys(all).length > 0) metadataAdmin.organization_roles = all
  else delete metadataAdmin.organization_roles
  return { ...state, metadataAdmin }
}

/** Exactly these roles in one organisation beyond plain membership (`member` is implied, never stored). */
export function setRoles(state: AdminState, organisationId: string, roles: readonly string[]): AdminState {
  return withRoles(state, organisationId, roles.filter((r) => r !== MEMBER))
}

/** Join one organisation, in one role. Idempotent; every other membership is left as it was. */
export function join(state: AdminState, organisationId: string, role = MEMBER): AdminState {
  let next = state
  if (!organisationsOn(state).includes(organisationId)) {
    next = state.organizationId
      ? withList(state, [...listed(state), organisationId])
      : { ...state, organizationId: organisationId }
  }
  if (role !== MEMBER) next = withRoles(next, organisationId, [...rolesIn(next, organisationId), role])
  return next
}

/**
 * Leave one organisation — or, with a role other than `member`, give up only that role there. When
 * it was the primary, the next one still held takes its place; with none left the primary is cleared.
 */
export function leave(state: AdminState, organisationId: string, role?: string): AdminState {
  if (role && role !== MEMBER) return withRoles(state, organisationId, rolesIn(state, organisationId).filter((r) => r !== role))
  const remaining = listed(state).filter((id) => id !== organisationId)
  let next = withRoles(state, organisationId, [])
  if (state.organizationId === organisationId) {
    const primary = remaining[0] ?? null
    next = withList({ ...next, organizationId: primary }, remaining.filter((id) => id !== primary))
  } else {
    next = withList(next, remaining)
  }
  return next
}

/**
 * Exactly this set. The primary stays when it is still in the set; otherwise the first one takes its
 * place. Roles in an organisation that was dropped go with it.
 */
export function setAll(state: AdminState, organisationIds: readonly string[], role = MEMBER): AdminState {
  const wanted = [...new Set(organisationIds.filter((id) => id.length > 0))]
  const primary = state.organizationId && wanted.includes(state.organizationId) ? state.organizationId : (wanted[0] ?? null)
  let next = withList({ ...state, organizationId: primary }, wanted.filter((id) => id !== primary))
  for (const org of Object.keys(rolesByOrganisation(state.metadataAdmin.organization_roles))) {
    if (!wanted.includes(org)) next = withRoles(next, org, [])
  }
  if (role !== MEMBER) for (const org of wanted) next = withRoles(next, org, [...rolesIn(next, org), role])
  return next
}
