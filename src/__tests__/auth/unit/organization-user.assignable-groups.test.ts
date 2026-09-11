import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// What the picker offers must be exactly what the mutation would accept. In this model that set is
// all-or-nothing: holding a group that grants in every organisation is the only authority over
// assignment it expresses, so there is no delegated, containment-bounded middle tier to mirror.
//
// What this file used to assert was that mirror — single-service groups narrowed to the service
// backing the organisation, with globals and multi-service groups excluded as defence in depth
// against OPA/Redis drift. All of it belonged to the retired model: grants are no longer keyed per
// service, and the engine path it asked stopped answering.

vi.mock('../../../services/authorization-model.service.js', () => ({
  assignableGroupsFor: vi.fn().mockResolvedValue([]),
  AuthorizationModelUnavailableError: class extends Error {},
}))

// The controller pulls these in at import time; stub the surface it touches so the module loads
// without real Redis, Kratos or a database.
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {},
  KratosApiError: class extends Error {},
}))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: {} }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn() } }))
vi.mock('../../../services/user-groups.service.js', () => ({ userGroupsService: {} }))
vi.mock('../../../services/organisation-store.js', () => ({
  addToGroup: vi.fn(),
  removeFromGroup: vi.fn(),
  removeMemberEverywhere: vi.fn(),
  forgetGroupsOf: vi.fn(),
}))
vi.mock('../../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { organizationUserController } from '../../../controllers/organization-user.controller.js'
import { assignableGroupsFor } from '../../../services/authorization-model.service.js'

function createReply(): FastifyReply & { _statusCode?: number; _body?: unknown } {
  const reply = {
    _statusCode: undefined as number | undefined,
    _body: undefined as unknown,
    status: vi.fn().mockImplementation(function (this: typeof reply, c: number) { this._statusCode = c; return this }),
    send: vi.fn().mockImplementation(function (this: typeof reply, b: unknown) { this._body = b; return this }),
  }
  return reply as unknown as FastifyReply & { _statusCode?: number; _body?: unknown }
}

function req(subject: string | undefined, organizationId = 'org-kuma') {
  return {
    params: { organizationId },
    userContext: subject ? { id: subject, email: `${subject}@example.com` } : undefined,
    log: { warn: vi.fn(), debug: vi.fn(), info: vi.fn() },
  } as unknown as FastifyRequest<{ Params: { organizationId: string } }>
}

describe('OrganizationUserController.listAssignableGroups', () => {
  beforeEach(() => vi.clearAllMocks())

  it('offers what the model says this subject may hand out', async () => {
    vi.mocked(assignableGroupsFor).mockResolvedValue(['platform-operator', 'premium-operator'])
    const reply = createReply()

    await organizationUserController.listAssignableGroups(req('subject-root'), reply)

    expect(reply._body).toEqual({ groups: ['platform-operator', 'premium-operator'] })
    // The IDENTITY, not the address: an address can be changed by its owner and reused by somebody
    // else, and this decides what somebody may hand out.
    expect(assignableGroupsFor).toHaveBeenCalledWith('subject-root')
  })

  it('offers nothing to a subject with no assignment authority', async () => {
    vi.mocked(assignableGroupsFor).mockResolvedValue([])
    const reply = createReply()

    await organizationUserController.listAssignableGroups(req('subject-plain'), reply)

    expect(reply._body).toEqual({ groups: [] })
  })

  it('does not vary by organisation, because the authority does not', async () => {
    // Asserted rather than left implicit: the route still carries an organisation, and a reader
    // could reasonably expect it to narrow the set. In this model it cannot.
    vi.mocked(assignableGroupsFor).mockResolvedValue(['platform-operator'])

    const first = createReply()
    await organizationUserController.listAssignableGroups(req('subject-root', 'org-a'), first)
    const second = createReply()
    await organizationUserController.listAssignableGroups(req('subject-root', 'org-b'), second)

    expect(first._body).toEqual(second._body)
  })

  it('refuses without an identity, before reading the model', async () => {
    const reply = createReply()

    await organizationUserController.listAssignableGroups(req(undefined), reply)

    expect(reply._statusCode).toBe(401)
    expect(assignableGroupsFor).not.toHaveBeenCalled()
  })

  it('answers 503 when the model cannot be read, never an empty list', async () => {
    // An empty list reads as "you may assign nothing", which is a legitimate answer. "I could not
    // read the model" is not, and must not be reported as one.
    vi.mocked(assignableGroupsFor).mockRejectedValue(new Error('configmaps is forbidden'))
    const reply = createReply()

    await organizationUserController.listAssignableGroups(req('subject-root'), reply)

    expect(reply._statusCode).toBe(503)
    expect(reply._body).toMatchObject({ error: 'Service Unavailable' })
  })
})
