import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { FastifyRequest } from 'fastify'

// The point of the setting is that a deployment can DELEGATE who belongs where. So the two modes
// must not leak into each other: in `claim` mode nothing may fall back to the local model, because
// a deployment that reads organisations from the token deliberately never populates it — and a
// fallback would turn "belongs to nothing" into "ask an administrator", which nobody can act on.

const { envState, opaModule, storeModule } = vi.hoisted(() => {
  const state = { env: { ORGANISATION_SOURCE: 'local' as 'local' | 'directory' | 'claim' } }
  return {
    envState: state,
    opaModule: { opaService: { manageableOrgs: vi.fn(async () => ['from-the-local-model']) } },
    storeModule: { organisationsForSubject: vi.fn(async () => ['from-the-directory']) },
  }
})

vi.mock('../../../config/index.js', () => ({ env: envState.env }))
vi.mock('../../../services/opa.service.js', () => opaModule)
vi.mock('../../../services/organisation-store.js', () => storeModule)

const { callerOrganisations, callerOrganisationsScope } = await import(
  '../../../services/caller-organisations.js'
)

function request(organisations?: string[], email = 'someone@strada.eu'): FastifyRequest {
  return { userContext: { email, id: 'an-id', name: 'Someone', organisations } } as FastifyRequest
}

describe('callerOrganisations', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    opaModule.opaService.manageableOrgs.mockResolvedValue(['from-the-local-model'])
  })

  describe('local mode — this service own model answers', () => {
    beforeEach(() => {
      envState.env.ORGANISATION_SOURCE = 'local'
    })

    it('asks the model', async () => {
      await expect(callerOrganisations(request(['from-the-token']), 'someone@strada.eu')).resolves.toEqual([
        'from-the-local-model',
      ])
      expect(opaModule.opaService.manageableOrgs).toHaveBeenCalledWith('someone@strada.eu')
    })

    it('answers nothing for a caller with no address to resolve', async () => {
      const anonymous = {} as FastifyRequest
      await expect(callerOrganisations(anonymous, undefined)).resolves.toEqual([])
      expect(opaModule.opaService.manageableOrgs).not.toHaveBeenCalled()
    })

    it('reports its scope as delegated, which is what it was called before', () => {
      expect(callerOrganisationsScope()).toBe('delegated')
    })
  })

  describe('directory mode — records this service owns answer', () => {
    beforeEach(() => {
      envState.env.ORGANISATION_SOURCE = 'directory'
      storeModule.organisationsForSubject.mockResolvedValue(['from-the-directory'])
    })

    it('asks the store by SUBJECT, not by address', async () => {
      // The subject is the one key that survives somebody changing their address, and the only one
      // the store can be asked about on behalf of a caller who is not that person.
      await expect(
        callerOrganisations(request(['from-the-token']), 'someone@strada.eu'),
      ).resolves.toEqual(['from-the-directory'])
      expect(storeModule.organisationsForSubject).toHaveBeenCalledWith('an-id')
      expect(opaModule.opaService.manageableOrgs).not.toHaveBeenCalled()
    })

    it('does NOT fall back to the inferred model, nor to the token', async () => {
      await expect(callerOrganisations(request([]), 'someone@strada.eu')).resolves.toEqual([
        'from-the-directory',
      ])
      expect(opaModule.opaService.manageableOrgs).not.toHaveBeenCalled()
    })

    it('answers nothing for a caller with no subject, without asking the store', async () => {
      await expect(callerOrganisations({} as FastifyRequest, 'someone@strada.eu')).resolves.toEqual([])
      expect(storeModule.organisationsForSubject).not.toHaveBeenCalled()
    })

    it('lets a store that cannot answer refuse, instead of reporting no membership', async () => {
      // Reporting none would turn an outage into a permission decision, which is the failure that
      // cannot be spotted from the outside.
      storeModule.organisationsForSubject.mockRejectedValue(new Error('store down'))
      await expect(callerOrganisations(request([]), 'someone@strada.eu')).rejects.toThrow('store down')
    })

    it('reports its scope as delegated: something here can still change the answer', () => {
      expect(callerOrganisationsScope()).toBe('delegated')
    })
  })

  describe('claim mode — the token answers', () => {
    beforeEach(() => {
      envState.env.ORGANISATION_SOURCE = 'claim'
    })

    it('asks neither the inferred model nor the store', async () => {
      await expect(callerOrganisations(request(['org-a']), 'someone@strada.eu')).resolves.toEqual([
        'org-a',
      ])
      expect(storeModule.organisationsForSubject).not.toHaveBeenCalled()
      expect(opaModule.opaService.manageableOrgs).not.toHaveBeenCalled()
    })

    it('reads the token and asks the model nothing', async () => {
      await expect(callerOrganisations(request(['org-a', 'org-b']), 'someone@strada.eu')).resolves.toEqual([
        'org-a',
        'org-b',
      ])
      expect(opaModule.opaService.manageableOrgs).not.toHaveBeenCalled()
    })

    it('does NOT fall back to the model when the token asserts none', async () => {
      // The whole point: a deployment that delegated this never fills the local model, so falling
      // back would answer with something the person cannot act on and cannot get changed.
      await expect(callerOrganisations(request([]), 'someone@strada.eu')).resolves.toEqual([])
      expect(opaModule.opaService.manageableOrgs).not.toHaveBeenCalled()
    })

    it('does NOT fall back when there is no claim at all', async () => {
      await expect(callerOrganisations(request(undefined), 'someone@strada.eu')).resolves.toEqual([])
      expect(opaModule.opaService.manageableOrgs).not.toHaveBeenCalled()
    })

    it('answers nothing for a caller with no context, without reaching for the model', async () => {
      await expect(callerOrganisations({} as FastifyRequest, 'someone@strada.eu')).resolves.toEqual([])
      expect(opaModule.opaService.manageableOrgs).not.toHaveBeenCalled()
    })

    it('hands back a copy, so a caller cannot edit what the token said', async () => {
      const carried = ['org-a']
      const answered = await callerOrganisations(request(carried), 'someone@strada.eu')
      answered.push('org-forged')
      expect(carried).toEqual(['org-a'])
    })

    it('reports its scope as claim, so a client can tell which authority answered', () => {
      expect(callerOrganisationsScope()).toBe('claim')
    })
  })
})
