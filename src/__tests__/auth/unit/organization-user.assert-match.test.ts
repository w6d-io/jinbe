import { describe, it, expect, vi } from 'vitest'

// organization-user.controller imports several services at module load.
// Stub them out so we can test the pure predicate in isolation without
// dragging the whole controller's dependency tree into the test.
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {},
  KratosApiError: class KratosApiError extends Error {
    statusCode: number
    constructor(statusCode: number, message: string) {
      super(message)
      this.statusCode = statusCode
    }
  },
}))

vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: {},
}))

vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn() },
}))

vi.mock('../../../services/user-groups.service.js', () => ({
  userGroupsService: {},
}))

import { assertOrganizationMatch } from '../../../controllers/organization-user.controller.js'
import type { KratosIdentity } from '../../../schemas/admin.schema.js'

const ORG_A = '11111111-1111-1111-1111-111111111111'
const ORG_B = '22222222-2222-2222-2222-222222222222'
const ORG_C = '33333333-3333-3333-3333-333333333333'

// Helper: build a minimal KratosIdentity-compatible object. Only the
// fields read by `assertOrganizationMatch` matter; the rest are filled
// with placeholder values to satisfy the TypeScript shape.
function makeIdentity(overrides: {
  organization_id?: string | null
  metadata_admin?: Record<string, unknown> | null
}): KratosIdentity {
  return {
    id: '00000000-0000-0000-0000-000000000000',
    schema_id: 'default',
    traits: { email: 'u@example.org' },
    metadata_admin: overrides.metadata_admin ?? null,
    organization_id: overrides.organization_id ?? null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  } as unknown as KratosIdentity
}

describe('assertOrganizationMatch (Path 3 hybrid)', () => {
  it('passes when orgId is in metadata_admin.organizations', () => {
    const identity = makeIdentity({
      metadata_admin: { organizations: [ORG_A, ORG_B] },
    })
    expect(() => assertOrganizationMatch(identity, ORG_A)).not.toThrow()
    expect(() => assertOrganizationMatch(identity, ORG_B)).not.toThrow()
  })

  it('passes when orgId equals the legacy organization_id pointer', () => {
    const identity = makeIdentity({ organization_id: ORG_A })
    expect(() => assertOrganizationMatch(identity, ORG_A)).not.toThrow()
  })

  it('passes when orgId matches via legacy pointer even when array is absent', () => {
    // Backward-compat case: an identity that has never been migrated to
    // the multi-org array still gets to access its single org.
    const identity = makeIdentity({
      organization_id: ORG_A,
      metadata_admin: null,
    })
    expect(() => assertOrganizationMatch(identity, ORG_A)).not.toThrow()
  })

  it('passes when orgId is in array AND differs from legacy pointer', () => {
    // Hybrid path: legacy pointer is one org, multi-org array contains
    // another. Either should grant access to its own org.
    const identity = makeIdentity({
      organization_id: ORG_A,
      metadata_admin: { organizations: [ORG_B] },
    })
    expect(() => assertOrganizationMatch(identity, ORG_A)).not.toThrow()
    expect(() => assertOrganizationMatch(identity, ORG_B)).not.toThrow()
  })

  it('rejects when orgId is in neither field', () => {
    const identity = makeIdentity({
      organization_id: ORG_A,
      metadata_admin: { organizations: [ORG_B] },
    })
    expect(() => assertOrganizationMatch(identity, ORG_C)).toThrow(
      /not found in this organization/,
    )
  })

  it('rejects when identity has no org context at all', () => {
    const identity = makeIdentity({})
    expect(() => assertOrganizationMatch(identity, ORG_A)).toThrow(
      /not found in this organization/,
    )
  })

  it('throws a 404-coded KratosApiError', () => {
    const identity = makeIdentity({})
    try {
      assertOrganizationMatch(identity, ORG_A)
      throw new Error('expected to throw')
    } catch (e) {
      expect((e as { statusCode: number }).statusCode).toBe(404)
    }
  })

  it('ignores non-string entries in metadata_admin.organizations', () => {
    // Defensive: if external tooling populates the array with non-string
    // values, the predicate must not throw a runtime error AND must not
    // accidentally accept them as a match. Only string entries count.
    const identity = makeIdentity({
      metadata_admin: { organizations: [42, null, ORG_A] as unknown[] },
    })
    expect(() => assertOrganizationMatch(identity, ORG_A)).not.toThrow()
    expect(() => assertOrganizationMatch(identity, ORG_B)).toThrow()
  })

  it('treats metadata_admin.organizations as missing when not an array', () => {
    const identity = makeIdentity({
      metadata_admin: { organizations: 'not-an-array' as unknown as string[] },
      organization_id: ORG_A,
    })
    // Falls back to the legacy pointer.
    expect(() => assertOrganizationMatch(identity, ORG_A)).not.toThrow()
    expect(() => assertOrganizationMatch(identity, ORG_B)).toThrow()
  })
})
