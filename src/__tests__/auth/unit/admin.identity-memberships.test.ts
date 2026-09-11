import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// The screen that EDITS memberships reads a SINGLE identity, computes its starting point from what
// it receives, and saves that. So the single-identity route answering without memberships is not a
// missing column: it is a screen that shows nothing and then writes nothing back.
//
// And the second half is the one that actually bit: the response serializer strips every property
// the schema does not name, silently. The controller can resolve memberships perfectly and the
// screen still receive an identity belonging nowhere.

const mockState = vi.hoisted(() => ({
  env: { APP_NAME: 'jinbe', ORGANISATION_SOURCE: 'directory' },
  held: new Map<string, string[]>(),
  membershipsFail: false,
}))

vi.mock('../../../config/env.js', () => ({ env: mockState.env }))

const IDENTITY = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  schema_id: 'default',
  state: 'active',
  traits: { email: 'somebody@strada.eu' },
  metadata_admin: {},
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getIdentity: vi.fn(async () => IDENTITY),
    listIdentities: vi.fn(async () => ({ identities: [IDENTITY], nextPageToken: undefined })),
    invalidateGroupsCache: vi.fn(),
  },
  KratosApiError: class extends Error {},
}))

vi.mock('../../../services/organisation-store.js', () => ({
  membershipsForSubjects: vi.fn(async () => {
    if (mockState.membershipsFail) throw new Error('store unavailable')
    return mockState.held
  }),
  setMemberships: vi.fn(async () => {}),
  groupsForSubjects: vi.fn(async () => new Map()),
}))

vi.mock('../../../services/authorization-model.service.js', () => ({
  platformRightsOf: vi.fn(async () => ({ groups: [], roles: [], permissions: [] })),
}))

vi.mock('../../../services/rbac.service.js', () => ({ rbacService: {} }))
vi.mock('../../../services/opa.service.js', () => ({ opalService: { getUserInfo: vi.fn(async () => null) } }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { record: vi.fn() } }))
vi.mock('../../../services/user-groups.service.js', () => ({ userGroupsService: {} }))
vi.mock('../../../server.js', () => ({ notificationService: { notify: vi.fn() } }))

const { AdminController } = await import('../../../controllers/admin.controller.js')
const { kratosIdentityJsonSchema } = await import('../../../schemas/admin.schema.js')

function request() {
  return { params: { id: IDENTITY.id }, query: {}, log: { error: vi.fn() } } as unknown as FastifyRequest<{
    Params: { id: string }
  }>
}

function reply() {
  const captured = { body: undefined as unknown }
  return {
    captured,
    send: vi.fn((body: unknown) => {
      captured.body = body
      return captured
    }),
    status: vi.fn(function (this: unknown) {
      return this
    }),
  } as unknown as FastifyReply & { captured: { body: unknown } }
}

describe('the single identity a drawer edits', () => {
  let controller: InstanceType<typeof AdminController>

  beforeEach(() => {
    vi.clearAllMocks()
    mockState.held = new Map([[IDENTITY.id, ['org-a', 'org-b', 'org-c']]])
    mockState.membershipsFail = false
    controller = new AdminController()
  })

  it('carries the memberships it holds, so opening the drawer shows the truth', async () => {
    const rep = reply()
    await controller.getUser(request(), rep)

    expect((rep.captured.body as { organizations?: string[] }).organizations).toEqual([
      'org-a',
      'org-b',
      'org-c',
    ])
  })

  it('answers with an empty set for somebody who belongs nowhere, not with nothing', async () => {
    // Absent and empty read the same on a screen but not to a reconciler: `[]` states the fact,
    // `undefined` invites the caller to invent one.
    mockState.held = new Map()

    const rep = reply()
    await controller.getUser(request(), rep)

    expect((rep.captured.body as { organizations?: string[] }).organizations).toEqual([])
  })

  it('still answers the identity when memberships cannot be read', async () => {
    // Whether somebody EXISTS must not depend on the membership store being up.
    mockState.membershipsFail = true

    const rep = reply()
    await controller.getUser(request(), rep)

    const body = rep.captured.body as { id: string; organizations?: string[] }
    expect(body.id).toBe(IDENTITY.id)
    expect(body.organizations).toBeUndefined()
  })
})

describe('the response schema', () => {
  // This is the test that would have caught the real defect. The serializer removes what the schema
  // does not name and says nothing about it, so the field has to be asserted where it is DECLARED,
  // not only where it is computed.
  it('names every field the controller adds, or the serializer removes it in silence', () => {
    const properties = kratosIdentityJsonSchema.properties as Record<string, unknown>
    for (const field of ['organizations', 'rbacUnavailable', 'groups', 'roles', 'permissions', 'credentials']) {
      expect(properties, `${field} is computed but not declared`).toHaveProperty(field)
    }
  })
})
