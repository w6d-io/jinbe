import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// Stories 8 and 9. Removing somebody from an organisation is about that organisation: the person,
// their other organisations and their site access stay. And somebody in two organisations is a
// member of both — the second one's admin sees them, not only the one written as primary.

const ACME = '11111111-1111-1111-1111-111111111111'
const GLOBEX = '22222222-2222-2222-2222-222222222222'
const BOB = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
const MIKE = 'cccccccc-cccc-cccc-cccc-cccccccccccc'

const state = vi.hoisted(() => ({
  env: { ORGANISATION_SOURCE: 'directory' as 'directory' | 'claim' },
  memberships: new Map<string, string[]>(),
  identities: new Map<string, Record<string, unknown>>(),
}))

vi.mock('../../../config/index.js', () => ({ env: state.env }))

vi.mock('../../../services/organisation-store.js', () => ({
  organisationStoreConfigured: vi.fn(() => true),
  organisationsForSubject: vi.fn(async (subject: string) => state.memberships.get(subject) ?? []),
  membersOf: vi.fn(async (org: string) =>
    [...state.memberships.entries()]
      .filter(([, orgs]) => orgs.includes(org))
      .map(([subjectId]) => ({ subjectId, role: 'member' })),
  ),
  addMember: vi.fn(async (org: string, subject: string) => {
    const held = state.memberships.get(subject) ?? []
    if (!held.includes(org)) state.memberships.set(subject, [...held, org])
  }),
  removeMember: vi.fn(async (org: string, subject: string) => {
    state.memberships.set(subject, (state.memberships.get(subject) ?? []).filter((o) => o !== org))
  }),
  removeMemberEverywhere: vi.fn(async (subject: string) => {
    state.memberships.delete(subject)
  }),
}))

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getIdentity: vi.fn(async (id: string) => {
      const identity = state.identities.get(id)
      if (!identity) throw Object.assign(new Error('not found'), { statusCode: 404 })
      return identity
    }),
    listIdentitiesByOrganization: vi.fn(async (org: string) => ({
      identities: [...state.identities.values()].filter((i) => i.organization_id === org),
    })),
    deleteIdentity: vi.fn(async () => {}),
    updateIdentity: vi.fn(async (id: string, data: Record<string, unknown>) => {
      const next = { ...state.identities.get(id), ...data }
      state.identities.set(id, next)
      return next
    }),
    patchIdentity: vi.fn(async (id: string, patches: { path: string; value: unknown }[]) => {
      const next = { ...state.identities.get(id) } as Record<string, unknown>
      for (const p of patches) next[p.path.replace(/^\//, '')] = p.value
      state.identities.set(id, next)
      return next
    }),
    invalidateGroupsCache: vi.fn(),
  },
  KratosApiError: class KratosApiError extends Error {
    statusCode: number
    constructor(statusCode: number, message: string) {
      super(message)
      this.statusCode = statusCode
    }
  },
}))

vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: { notifyBindingsChanged: vi.fn().mockResolvedValue(undefined) },
}))
vi.mock('../../../services/user-groups.service.js', () => ({ userGroupsService: {} }))
vi.mock('../../../services/authorization-model.service.js', () => ({
  assignableGroupsFor: vi.fn(),
  declaredGroups: vi.fn(),
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))
vi.mock('../../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { organizationUserController } from '../../../controllers/organization-user.controller.js'
import { kratosService } from '../../../services/kratos.service.js'
import { removeMemberEverywhere } from '../../../services/organisation-store.js'

function reply() {
  const r = {
    code: undefined as number | undefined,
    body: undefined as unknown,
    status: vi.fn(function (this: typeof r, code: number) {
      this.code = code
      return this
    }),
    send: vi.fn(function (this: typeof r, body?: unknown) {
      this.body = body
      return this
    }),
  }
  return r as typeof r & FastifyReply
}

function req(params: Record<string, string>, query: Record<string, string> = {}) {
  return {
    params,
    query,
    ip: '127.0.0.1',
    userContext: { id: 'subject-olivia', email: 'olivia@acme.test' },
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  } as unknown as FastifyRequest<never>
}

function identity(id: string, primary: string | null, listed: string[] = []) {
  return {
    id,
    schema_id: 'default',
    state: 'active',
    traits: { email: `${id.slice(0, 4)}@example.com` },
    organization_id: primary,
    metadata_admin: { groups: ['users'], organizations: listed },
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  state.env.ORGANISATION_SOURCE = 'directory'
  state.memberships = new Map([
    [BOB, [ACME, GLOBEX]],
    [MIKE, [ACME]],
  ])
  state.identities = new Map([
    [BOB, identity(BOB, ACME, [GLOBEX])],
    [MIKE, identity(MIKE, ACME)],
  ])
})

describe('removing somebody from an organisation (story 8)', () => {
  it('never deletes the identity', async () => {
    const r = reply()
    await organizationUserController.deleteUser(req({ organizationId: ACME, id: MIKE }), r)

    expect(r.code).toBe(204)
    expect(kratosService.deleteIdentity).not.toHaveBeenCalled()
    expect(state.identities.has(MIKE)).toBe(true)
  })

  it('drops only that membership — Bob removed from Acme keeps Globex', async () => {
    const r = reply()
    await organizationUserController.deleteUser(req({ organizationId: ACME, id: BOB }), r)

    expect(removeMemberEverywhere).not.toHaveBeenCalled()
    expect(state.memberships.get(BOB)).toEqual([GLOBEX])
  })

  it('takes the organisation off the identity too, so the next console edit does not put it back', async () => {
    await organizationUserController.deleteUser(req({ organizationId: ACME, id: BOB }), reply())

    const after = state.identities.get(BOB) as ReturnType<typeof identity>
    // Primary moves to the organisation they still belong to; the list no longer names Acme.
    expect(after.organization_id).toBe(GLOBEX)
    expect(after.metadata_admin.organizations).not.toContain(ACME)
    expect(after.metadata_admin.groups).toEqual(['users'])
  })

  it('clears the primary organisation when it was the only one', async () => {
    await organizationUserController.deleteUser(req({ organizationId: ACME, id: MIKE }), reply())

    expect(state.identities.get(MIKE)?.organization_id).toBeNull()
    expect(state.memberships.get(MIKE)).toEqual([])
  })

  it('refuses with 404 for somebody who is not a member', async () => {
    state.identities.set(MIKE, identity(MIKE, GLOBEX))
    state.memberships.set(MIKE, [GLOBEX])

    await expect(
      organizationUserController.deleteUser(req({ organizationId: ACME, id: MIKE }), reply()),
    ).rejects.toMatchObject({ statusCode: 404 })
    expect(state.memberships.get(MIKE)).toEqual([GLOBEX])
  })
})

describe('somebody in two organisations (story 9)', () => {
  it("lists them to the admin of their second organisation", async () => {
    const r = reply()
    await organizationUserController.listUsers(req({ organizationId: GLOBEX }), r)

    const ids = (r.body as { data: { id: string }[] }).data.map((i) => i.id)
    expect(ids).toEqual([BOB])
  })

  it('does not list the same person twice', async () => {
    const r = reply()
    await organizationUserController.listUsers(req({ organizationId: ACME }), r)

    const ids = (r.body as { data: { id: string }[] }).data.map((i) => i.id).sort()
    expect(ids).toEqual([BOB, MIKE].sort())
  })

  it('lets the second organisation read them', async () => {
    const r = reply()
    await organizationUserController.getUser(req({ organizationId: GLOBEX, id: BOB }), r)

    expect((r.body as { id: string }).id).toBe(BOB)
  })

  it('adds an existing person to another organisation without touching the first', async () => {
    const r = reply()
    await organizationUserController.addMembership(req({ organizationId: GLOBEX, id: MIKE }), r)

    expect(r.code).toBe(200)
    expect(state.memberships.get(MIKE)).toEqual([ACME, GLOBEX])
    const after = state.identities.get(MIKE) as ReturnType<typeof identity>
    expect(after.organization_id).toBe(ACME)
    expect(after.metadata_admin.organizations).toEqual([GLOBEX])
  })

  it('makes the first organisation primary for somebody who had none', async () => {
    state.identities.set(MIKE, identity(MIKE, null))
    state.memberships.set(MIKE, [])

    await organizationUserController.addMembership(req({ organizationId: GLOBEX, id: MIKE }), reply())

    expect(state.identities.get(MIKE)?.organization_id).toBe(GLOBEX)
    expect(state.memberships.get(MIKE)).toEqual([GLOBEX])
  })
})
