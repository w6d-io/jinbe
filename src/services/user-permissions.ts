import { CATALOG, effectivePermissions, grants, type Permission } from '../policy/catalog.js'

/** What a user-management check may name: a catalogue permission (policy/catalog.ts). */
export type CheckedPermission = Permission

/** Whether these held permissions allow the required one (exactly itself). */
export function allows(held: readonly string[], required: string): boolean {
  return grants(held, required)
}

/**
 * The administrative rights among these held names: every catalogue permission above `low`
 * sensitivity. Everyday site permissions are left out: an administrator
 * can hand those out anyway. What a takeover-shaped action (removing a second factor, changing the
 * sign-in address) compares: nobody may do it to somebody holding one they do not.
 */
export function administrativePermissions(held: readonly string[]): Permission[] {
  return effectivePermissions(held).filter((p) => CATALOG[p].sensitivity !== 'low')
}

/** Administrative rights `theirs` holds that `mine` does not. */
export function outranking(theirs: readonly string[], mine: readonly string[]): Permission[] {
  return administrativePermissions(theirs).filter((p) => !grants(mine, p))
}

/** The user-management actions a console offers, in the order it lists them. */
const USER_ACTIONS: readonly Permission[] = [
  'users:read', 'users:create', 'users:update', 'users:update_email', 'users:disable', 'users:delete',
  'users:recovery', 'users:verify', 'users:send_login_link', 'users:reset_second_factor',
  'sessions:read', 'sessions:revoke', 'groups.members:write', 'groups.members:revoke',
]

/**
 * What a console may offer this caller: each user-management action, and whether it is allowed.
 * Every key is always present, so a missing one can never be read as "allowed".
 */
export function userActions(held: readonly string[]): Record<string, boolean> {
  const out: Record<string, boolean> = {}
  for (const p of USER_ACTIONS) out[p] = grants(held, p)
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

/** Outside the traits: the state is deactivation (`users:disable`), the rest `users.metadata:write`. */
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
    if (!sameValue(next, stored)) required.add(field === 'state' ? 'users:disable' : 'users.metadata:write')
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
