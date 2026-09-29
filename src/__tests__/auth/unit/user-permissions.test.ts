import { describe, it, expect } from 'vitest'
import { allows, requiredForEdit, userActions } from '../../../services/user-permissions.js'

describe('a catalogue permission, held or through a legacy alias', () => {
  it('holding it, or the coarse permission it refines, or `*`, allows it', () => {
    expect(allows(['users:update_email'], 'users:update_email')).toBe(true)
    expect(allows(['admin:write'], 'users:update_email')).toBe(true)
    expect(allows(['*'], 'users:delete')).toBe(true)
  })

  it('reads come from admin:read, writes only from admin:write', () => {
    expect(allows(['admin:read'], 'users:read')).toBe(true)
    expect(allows(['admin:read'], 'sessions:read')).toBe(true)
    expect(allows(['admin:read'], 'users:delete')).toBe(false)
    expect(allows(['admin:read'], 'sessions:revoke')).toBe(false)
  })

  it('one fine permission implies no other', () => {
    expect(allows(['users:update'], 'users:update_email')).toBe(false)
    expect(allows(['sessions:read'], 'sessions:revoke')).toBe(false)
    expect(allows(['users:read'], 'admin:read')).toBe(false)
  })

  it('every action is answered, true or false — the legacy keys kuma reads included', () => {
    const actions = userActions([])
    expect(Object.keys(actions)).toEqual(expect.arrayContaining(['users:read', 'users:disable', 'users:verify', 'groups.members:revoke', 'admin:read', 'admin:write', 'users:assign_group']))
    expect(Object.values(actions).some(Boolean)).toBe(false)
    expect(userActions(['admin:write'])['users:assign_group']).toBe(true)
  })
})

describe('an edit requires what it changes', () => {
  const bob = { state: 'active', traits: { email: 'bob@example.com', name: 'Bob' }, metadata_admin: { groups: ['users'], note: 'x' } }

  it('the name → users:update; the address → users:update_email; both → both', () => {
    expect(requiredForEdit(bob, { traits: { name: 'Robert' } })).toEqual(['users:update'])
    expect(requiredForEdit(bob, { traits: { email: 'rob@example.com' } })).toEqual(['users:update_email'])
    expect(requiredForEdit(bob, { traits: { name: 'Robert', email: 'rob@example.com' } }).sort()).toEqual(['users:update', 'users:update_email'])
  })

  it('a field resent unchanged asks for nothing; re-casing the address is not a new address', () => {
    expect(requiredForEdit(bob, { traits: { email: ' BOB@example.com', name: 'Robert' } })).toEqual(['users:update'])
    expect(requiredForEdit(bob, { state: 'active', traits: { name: 'Robert' } })).toEqual(['users:update'])
  })

  it('the state is deactivation; the rest outside the traits is users.metadata:write', () => {
    expect(requiredForEdit(bob, { state: 'inactive' })).toEqual(['users:disable'])
    expect(requiredForEdit(bob, { metadata_admin: { groups: ['users'], note: 'y' } })).toEqual(['users.metadata:write'])
    expect(requiredForEdit(bob, { metadata_public: { a: 1 } })).toEqual(['users.metadata:write'])
  })

  it('pinned membership is not compared (the handler refuses a change to it)', () => {
    expect(requiredForEdit(bob, { metadata_admin: { groups: ['super_admins'], note: 'x' } })).toEqual(['users:update'])
  })

  it('an edit that changes nothing still needs the right to edit', () => {
    expect(requiredForEdit(bob, {})).toEqual(['users:update'])
  })
})
