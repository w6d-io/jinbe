import { permits } from './authorization-resolution.js'

/**
 * The user-management permissions, one per thing a person at a support desk may be allowed to do.
 *
 * They REFINE the administration API rather than replace it: whoever holds the coarse permission a
 * row names keeps every action under it, so the admin roles that carry `admin:read` / `admin:write`
 * (or `*` in the retired per-service model) work exactly as before. Only a caller holding nothing but
 * the fine permissions — the support role — is confined to them.
 *
 * Reading needs `admin:read`, writing `admin:write`: before this, every user write sat behind the
 * plugin's `admin:read` gate alone, so a read-only administrator could delete a user.
 */
export const USER_PERMISSIONS = {
  'users:read': 'admin:read',
  'users:create': 'admin:write',
  'users:update': 'admin:write',
  'users:update_email': 'admin:write',
  'users:delete': 'admin:write',
  'users:assign_group': 'admin:write',
  'sessions:read': 'admin:read',
  'sessions:revoke': 'admin:write',
  'users:recovery': 'admin:write',
  'users:send_login_link': 'admin:write',
} as const

export type UserPermission = keyof typeof USER_PERMISSIONS

/** Every permission a check here may name: the fine ones and the coarse ones they refine. */
export type CheckedPermission = UserPermission | 'admin:read' | 'admin:write'

/** The wildcard of the per-service model. The tree model has none, so it only ever appears there. */
const EVERYTHING = '*'

/** Whether these held permissions allow the required one. */
export function allows(held: readonly string[], required: CheckedPermission): boolean {
  if (held.includes(EVERYTHING)) return true
  if (permits(held, required)) return true
  const coarse = (USER_PERMISSIONS as Record<string, string>)[required]
  return coarse !== undefined && permits(held, coarse)
}

/**
 * What a console may offer this caller: each user-management action, and whether it is allowed.
 * Every key is always present, so a missing one can never be read as "allowed".
 */
export function userActions(held: readonly string[]): Record<CheckedPermission, boolean> {
  const out = {} as Record<CheckedPermission, boolean>
  for (const p of [...Object.keys(USER_PERMISSIONS), 'admin:read', 'admin:write'] as CheckedPermission[]) {
    out[p] = allows(held, p)
  }
  return out
}

/** The parts of an identity an edit can reach. */
export interface EditableIdentity {
  schema_id?: unknown
  state?: unknown
  traits?: Record<string, unknown>
  metadata_public?: unknown
  metadata_admin?: unknown
}

/** Outside the traits: an administrator's business, not a support desk's. */
const ADMINISTRATIVE_FIELDS = ['schema_id', 'state', 'metadata_public', 'metadata_admin'] as const

/**
 * What an edit of `current` into `incoming` requires — by what it CHANGES, not by what it sends.
 *
 * `PUT /admin/users/:id` merges `traits` over the stored ones, and a console may resend fields it
 * did not touch, so a field present with its stored value asks for nothing. The address is compared
 * the way a mailbox is (trimmed, case-insensitive): re-casing it is not a change of address.
 * Membership (`metadata_admin.groups`) is pinned by the handler and never changes here, so it is
 * left out of the comparison.
 */
export function requiredForEdit(current: EditableIdentity, incoming: EditableIdentity): CheckedPermission[] {
  const required = new Set<CheckedPermission>()

  for (const [key, value] of Object.entries(incoming.traits ?? {})) {
    const stored = current.traits?.[key]
    if (key === 'email') {
      if (normaliseAddress(value) !== normaliseAddress(stored)) required.add('users:update_email')
    } else if (!sameValue(value, stored)) {
      required.add('users:update')
    }
  }

  for (const field of ADMINISTRATIVE_FIELDS) {
    if (!(field in incoming) || incoming[field] === undefined) continue
    const next = field === 'metadata_admin' ? withoutGroups(incoming[field]) : incoming[field]
    const stored = field === 'metadata_admin' ? withoutGroups(current[field]) : current[field]
    if (!sameValue(next, stored)) required.add('admin:write')
  }

  // An edit that changes nothing still is one: it needs the right to edit.
  if (required.size === 0) required.add('users:update')
  return [...required]
}

function normaliseAddress(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : JSON.stringify(value ?? null)
}

function withoutGroups(meta: unknown): unknown {
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return meta ?? {}
  const { groups: _pinned, ...rest } = meta as Record<string, unknown>
  return rest
}

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(canonical(a ?? null)) === JSON.stringify(canonical(b ?? null))
}

function canonical(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(canonical)
  return Object.fromEntries(
    Object.keys(value as Record<string, unknown>).sort().map((k) => [k, canonical((value as Record<string, unknown>)[k])]),
  )
}
