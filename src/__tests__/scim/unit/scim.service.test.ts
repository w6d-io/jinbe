import { describe, it, expect, beforeEach, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  getIdentity: vi.fn(),
  createIdentity: vi.fn(),
  updateIdentity: vi.fn(),
  findByEmail: vi.fn(),
  listIdentities: vi.fn(),
  revokeAllIdentitySessions: vi.fn(),
  invalidateGroupsCache: vi.fn(),
}))

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: mocks,
  KratosApiError: class KratosApiError extends Error {
    constructor(public statusCode: number, message: string) {
      super(message)
    }
  },
}))

import { ScimService, ScimError } from '../../../services/scim.service.js'
import { KratosApiError } from '../../../services/kratos.service.js'

const identity = (overrides: Record<string, unknown> = {}) => ({
  id: '2819c223-7f76-453a-919d-413861904646',
  schema_id: 'default',
  state: 'active',
  traits: { email: 'babs@jensen.org', name: 'Barbara Jensen' },
  metadata_admin: { groups: ['users'] },
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
  ...overrides,
}) as never

describe('ScimService', () => {
  let service: ScimService

  beforeEach(() => {
    vi.clearAllMocks()
    service = new ScimService()
    mocks.revokeAllIdentitySessions.mockResolvedValue(undefined)
  })

  describe('toScimUser — identity → RFC 7643 User mapping', () => {
    it('maps traits, state, groups and meta', () => {
      const user = service.toScimUser(identity()) as Record<string, any>
      expect(user.schemas).toEqual(['urn:ietf:params:scim:schemas:core:2.0:User'])
      expect(user.id).toBe('2819c223-7f76-453a-919d-413861904646')
      expect(user.userName).toBe('babs@jensen.org')
      expect(user.emails).toEqual([{ value: 'babs@jensen.org', primary: true }])
      expect(user.name).toEqual({ formatted: 'Barbara Jensen', givenName: 'Barbara', familyName: 'Jensen' })
      expect(user.active).toBe(true)
      expect(user.groups).toEqual([{ value: 'users', display: 'users', type: 'direct' }])
      expect(user.meta).toEqual({
        resourceType: 'User',
        created: '2026-01-01T00:00:00Z',
        lastModified: '2026-01-02T00:00:00Z',
        location: '/scim/v2/Users/2819c223-7f76-453a-919d-413861904646',
      })
      expect(user.externalId).toBeUndefined()
    })

    it('surfaces externalId from metadata_admin.scim and inactive state', () => {
      const user = service.toScimUser(
        identity({
          state: 'inactive',
          metadata_admin: { groups: ['users'], scim: { externalId: 'ext-42', managed: true } },
        })
      ) as Record<string, any>
      expect(user.externalId).toBe('ext-42')
      expect(user.active).toBe(false)
    })
  })

  describe('parseFilter — whitelist, no full grammar', () => {
    it('parses userName eq (attribute + operator case-insensitive)', () => {
      expect(service.parseFilter('userName eq "x@y.z"')).toEqual({ attribute: 'userName', value: 'x@y.z' })
      expect(service.parseFilter('USERNAME EQ "x@y.z"')).toEqual({ attribute: 'userName', value: 'x@y.z' })
      expect(service.parseFilter('externalId eq "abc"')).toEqual({ attribute: 'externalId', value: 'abc' })
    })

    it('returns null for no filter', () => {
      expect(service.parseFilter(undefined)).toBeNull()
      expect(service.parseFilter('  ')).toBeNull()
    })

    it('rejects any other filter with 501 (incl. injection attempts)', () => {
      for (const bad of [
        'displayName eq "x"',
        'userName co "x"',
        'userName eq "a" or userName eq "b"',
        'userName eq "x") or (1 eq 1',
      ]) {
        try {
          service.parseFilter(bad)
          expect.unreachable(`should have thrown for: ${bad}`)
        } catch (err) {
          expect(err).toBeInstanceOf(ScimError)
          expect((err as ScimError).status).toBe(501)
        }
      }
    })
  })

  describe('listUsers — filter + pagination', () => {
    it('userName eq uses the exact-match Kratos lookup (lowercased)', async () => {
      mocks.findByEmail.mockResolvedValue(identity())
      const result = await service.listUsers({ filter: 'userName eq "Babs@Jensen.org"' })
      expect(mocks.findByEmail).toHaveBeenCalledWith('babs@jensen.org')
      expect(result.totalResults).toBe(1)
      expect(result.itemsPerPage).toBe(1)
      expect((result.resources[0] as any).userName).toBe('babs@jensen.org')
    })

    it('userName eq with no match → empty ListResponse data', async () => {
      mocks.findByEmail.mockResolvedValue(null)
      const result = await service.listUsers({ filter: 'userName eq "ghost@x.dev"' })
      expect(result).toMatchObject({ totalResults: 0, startIndex: 1, itemsPerPage: 0, resources: [] })
    })

    it('paginates with 1-based startIndex and count', async () => {
      const ids = ['a', 'b', 'c', 'd'].map((n) =>
        identity({ id: `00000000-0000-0000-0000-00000000000${n}`, traits: { email: `${n}@x.dev` } })
      )
      mocks.listIdentities.mockResolvedValue({ identities: ids, nextPageToken: undefined })
      const result = await service.listUsers({ startIndex: 2, count: 2 })
      expect(result.totalResults).toBe(4)
      expect(result.startIndex).toBe(2)
      expect(result.itemsPerPage).toBe(2)
      expect(result.resources.map((r: any) => r.userName)).toEqual(['b@x.dev', 'c@x.dev'])
    })

    it('clamps startIndex < 1 to 1 and count < 0 to 0 (RFC 7644 §3.4.2.4)', async () => {
      mocks.listIdentities.mockResolvedValue({ identities: [identity()], nextPageToken: undefined })
      const low = await service.listUsers({ startIndex: 0 })
      expect(low.startIndex).toBe(1)
      expect(low.itemsPerPage).toBe(1)
      const zero = await service.listUsers({ count: -5 })
      expect(zero.itemsPerPage).toBe(0)
      expect(zero.totalResults).toBe(1)
    })

    it('externalId eq filters the full directory walk', async () => {
      mocks.listIdentities.mockResolvedValue({
        identities: [
          identity(),
          identity({
            id: '00000000-0000-0000-0000-000000000002',
            traits: { email: 'ext@x.dev' },
            metadata_admin: { scim: { externalId: 'ext-42' } },
          }),
        ],
        nextPageToken: undefined,
      })
      const result = await service.listUsers({ filter: 'externalId eq "ext-42"' })
      expect(result.totalResults).toBe(1)
      expect((result.resources[0] as any).userName).toBe('ext@x.dev')
    })
  })

  describe('createUser', () => {
    it('creates the Kratos identity with default group and scim.managed marking', async () => {
      mocks.findByEmail.mockResolvedValue(null)
      mocks.createIdentity.mockResolvedValue(identity())
      await service.createUser(
        {
          userName: 'Babs@Jensen.org',
          externalId: 'ext-42',
          name: { givenName: 'Barbara', familyName: 'Jensen' },
        },
        'tok1'
      )
      expect(mocks.createIdentity).toHaveBeenCalledWith({
        schema_id: 'default',
        state: 'active',
        traits: { email: 'babs@jensen.org', name: 'Barbara Jensen' },
        metadata_admin: {
          groups: ['users'],
          scim: expect.objectContaining({ externalId: 'ext-42', managed: true, idp: 'tok1' }),
        },
      })
      expect(mocks.invalidateGroupsCache).toHaveBeenCalled()
    })

    it('rejects an existing email with 409 uniqueness (adoption via GET+PATCH, spec §4)', async () => {
      mocks.findByEmail.mockResolvedValue(identity())
      await expect(
        service.createUser({ userName: 'babs@jensen.org' }, 'tok1')
      ).rejects.toMatchObject({ status: 409, scimType: 'uniqueness' })
      expect(mocks.createIdentity).not.toHaveBeenCalled()
    })

    it('rejects a body without userName or email with 400 invalidValue', async () => {
      await expect(service.createUser({}, 'tok1')).rejects.toMatchObject({
        status: 400,
        scimType: 'invalidValue',
      })
    })

    it('falls back to the primary email when userName is absent', async () => {
      mocks.findByEmail.mockResolvedValue(null)
      mocks.createIdentity.mockResolvedValue(identity())
      await service.createUser(
        { emails: [{ value: 'second@x.dev' }, { value: 'primary@x.dev', primary: true }] },
        'tok1'
      )
      expect(mocks.createIdentity).toHaveBeenCalledWith(
        expect.objectContaining({ traits: { email: 'primary@x.dev' } })
      )
    })

    it('honours active=false on create', async () => {
      mocks.findByEmail.mockResolvedValue(null)
      mocks.createIdentity.mockResolvedValue(identity({ state: 'inactive' }))
      await service.createUser({ userName: 'x@y.dev', active: false }, 'tok1')
      expect(mocks.createIdentity).toHaveBeenCalledWith(expect.objectContaining({ state: 'inactive' }))
    })
  })

  describe('replaceUser (PUT)', () => {
    it('replaces traits and preserves groups, writing scim metadata', async () => {
      mocks.getIdentity.mockResolvedValue(identity({ metadata_admin: { groups: ['users', 'admins'] } }))
      mocks.updateIdentity.mockResolvedValue(identity())
      await service.replaceUser(
        '2819c223-7f76-453a-919d-413861904646',
        { userName: 'babs@jensen.org', name: { givenName: 'Barb', familyName: 'J' }, active: true, externalId: 'ext-9' },
        'tok1'
      )
      expect(mocks.updateIdentity).toHaveBeenCalledWith('2819c223-7f76-453a-919d-413861904646', {
        traits: { email: 'babs@jensen.org', name: 'Barb J' },
        state: 'active',
        metadata_admin: {
          groups: ['users', 'admins'],
          scim: expect.objectContaining({ externalId: 'ext-9', managed: true, idp: 'tok1' }),
        },
      })
    })

    it('rejects changing the email to one owned by another identity (409)', async () => {
      mocks.getIdentity.mockResolvedValue(identity())
      mocks.findByEmail.mockResolvedValue(identity({ id: '00000000-0000-0000-0000-000000000009' }))
      await expect(
        service.replaceUser('2819c223-7f76-453a-919d-413861904646', { userName: 'taken@x.dev' }, 'tok1')
      ).rejects.toMatchObject({ status: 409, scimType: 'uniqueness' })
    })

    it('404s on an unknown identity as a ScimError', async () => {
      mocks.getIdentity.mockRejectedValue(new KratosApiError(404, 'not found'))
      await expect(service.replaceUser('missing', {}, 'tok1')).rejects.toMatchObject({ status: 404 })
    })
  })

  describe('patchUser (RFC 7644 PatchOp)', () => {
    it('replace active=false deactivates and revokes sessions', async () => {
      mocks.getIdentity.mockResolvedValue(identity())
      mocks.updateIdentity.mockResolvedValue(identity({ state: 'inactive' }))
      const user = await service.patchUser(
        '2819c223-7f76-453a-919d-413861904646',
        { Operations: [{ op: 'replace', path: 'active', value: false }] },
        'tok1'
      )
      expect(mocks.updateIdentity).toHaveBeenCalledWith(
        '2819c223-7f76-453a-919d-413861904646',
        expect.objectContaining({ state: 'inactive' })
      )
      expect(mocks.revokeAllIdentitySessions).toHaveBeenCalledWith('2819c223-7f76-453a-919d-413861904646')
      expect((user as any).active).toBe(false)
    })

    it('accepts Entra-style stringly booleans and Replace casing', async () => {
      mocks.getIdentity.mockResolvedValue(identity())
      mocks.updateIdentity.mockResolvedValue(identity({ state: 'inactive' }))
      await service.patchUser(
        '2819c223-7f76-453a-919d-413861904646',
        { Operations: [{ op: 'Replace', path: 'active', value: 'False' }] },
        'tok1'
      )
      expect(mocks.updateIdentity).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ state: 'inactive' })
      )
    })

    it('reactivates without revoking sessions', async () => {
      mocks.getIdentity.mockResolvedValue(identity({ state: 'inactive' }))
      mocks.updateIdentity.mockResolvedValue(identity())
      await service.patchUser(
        '2819c223-7f76-453a-919d-413861904646',
        { Operations: [{ op: 'replace', path: 'active', value: true }] },
        'tok1'
      )
      expect(mocks.updateIdentity).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ state: 'active' })
      )
      expect(mocks.revokeAllIdentitySessions).not.toHaveBeenCalled()
    })

    it('applies a no-path object value (RFC 7644 §3.5.2.1)', async () => {
      mocks.getIdentity.mockResolvedValue(identity())
      mocks.updateIdentity.mockResolvedValue(identity({ state: 'inactive' }))
      await service.patchUser(
        '2819c223-7f76-453a-919d-413861904646',
        { Operations: [{ op: 'replace', value: { active: false, displayName: 'New Name' } }] },
        'tok1'
      )
      expect(mocks.updateIdentity).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          state: 'inactive',
          traits: expect.objectContaining({ name: 'New Name' }),
        })
      )
    })

    it('composes name.givenName / name.familyName path ops', async () => {
      mocks.getIdentity.mockResolvedValue(identity())
      mocks.updateIdentity.mockResolvedValue(identity())
      await service.patchUser(
        '2819c223-7f76-453a-919d-413861904646',
        {
          Operations: [
            { op: 'replace', path: 'name.givenName', value: 'Barb' },
            { op: 'replace', path: 'name.familyName', value: 'Jay' },
          ],
        },
        'tok1'
      )
      expect(mocks.updateIdentity).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ traits: expect.objectContaining({ name: 'Barb Jay' }) })
      )
    })

    it('rejects a missing Operations array (400 invalidSyntax)', async () => {
      await expect(service.patchUser('x', {}, 'tok1')).rejects.toMatchObject({
        status: 400,
        scimType: 'invalidSyntax',
      })
    })

    it('rejects an unknown op (400 invalidSyntax)', async () => {
      mocks.getIdentity.mockResolvedValue(identity())
      await expect(
        service.patchUser('x', { Operations: [{ op: 'move', path: 'active', value: true }] }, 'tok1')
      ).rejects.toMatchObject({ status: 400, scimType: 'invalidSyntax' })
    })

    it('rejects a non-boolean active value (400 invalidValue)', async () => {
      mocks.getIdentity.mockResolvedValue(identity())
      await expect(
        service.patchUser('x', { Operations: [{ op: 'replace', path: 'active', value: 'maybe' }] }, 'tok1')
      ).rejects.toMatchObject({ status: 400, scimType: 'invalidValue' })
    })
  })

  describe('deactivateUser (DELETE → soft delete)', () => {
    it('sets state inactive + revokes sessions, never deleteIdentity', async () => {
      mocks.getIdentity.mockResolvedValue(identity())
      mocks.updateIdentity.mockResolvedValue(identity({ state: 'inactive' }))
      await service.deactivateUser('2819c223-7f76-453a-919d-413861904646', 'tok1')
      expect(mocks.updateIdentity).toHaveBeenCalledWith(
        '2819c223-7f76-453a-919d-413861904646',
        expect.objectContaining({ state: 'inactive' })
      )
      expect(mocks.revokeAllIdentitySessions).toHaveBeenCalled()
      expect((mocks as Record<string, unknown>).deleteIdentity).toBeUndefined()
    })
  })
})
