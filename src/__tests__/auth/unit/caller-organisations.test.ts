import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { FastifyRequest } from 'fastify'

// The point of the setting is that a deployment can DELEGATE who belongs where. So the two modes
// must not leak into each other: in `claim` mode nothing may fall back to the directory, because a
// deployment that reads organisations from the token deliberately never populates it — and a
// fallback would turn "belongs to nothing" into "ask an administrator", which nobody can act on.
//
// There was a third mode, `local`, and it was the DEFAULT: it asked an engine for a path that
// stopped existing when the model became `strada.authz`. It answered nothing, so it scoped every
// caller to no organisation at all, and any deployment that did not set this variable fell into it.

const { envState, storeModule } = vi.hoisted(() => ({
  envState: { env: { ORGANISATION_SOURCE: 'directory' as 'directory' | 'claim' } },
  storeModule: { organisationsForSubject: vi.fn(async () => ['from-the-directory']) },
}))

vi.mock('../../../config/index.js', () => ({ env: envState.env }))
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
    storeModule.organisationsForSubject.mockResolvedValue(['from-the-directory'])
    envState.env.ORGANISATION_SOURCE = 'directory'
  })

  it('answers from the directory by default, which is where they are held', () => {
    // The default matters as much as the modes: the one before this asked an engine that had stopped
    // answering, so an unconfigured deployment scoped everybody to nothing.
    expect(callerOrganisationsScope()).toBe('delegated')
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
        callerOrganisations(request(['from-the-token'])),
      ).resolves.toEqual(['from-the-directory'])
      expect(storeModule.organisationsForSubject).toHaveBeenCalledWith('an-id')
    })

    it('does NOT fall back to the inferred model, nor to the token', async () => {
      await expect(callerOrganisations(request([]))).resolves.toEqual([
        'from-the-directory',
      ])
    })

    it('answers nothing for a caller with no subject, without asking the store', async () => {
      await expect(callerOrganisations({} as FastifyRequest, 'someone@strada.eu')).resolves.toEqual([])
      expect(storeModule.organisationsForSubject).not.toHaveBeenCalled()
    })

    it('lets a store that cannot answer refuse, instead of reporting no membership', async () => {
      // Reporting none would turn an outage into a permission decision, which is the failure that
      // cannot be spotted from the outside.
      storeModule.organisationsForSubject.mockRejectedValue(new Error('store down'))
      await expect(callerOrganisations(request([]))).rejects.toThrow('store down')
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
      await expect(callerOrganisations(request(['org-a']))).resolves.toEqual([
        'org-a',
      ])
      expect(storeModule.organisationsForSubject).not.toHaveBeenCalled()
    })

    it('reads the token and asks the model nothing', async () => {
      await expect(callerOrganisations(request(['org-a', 'org-b']))).resolves.toEqual([
        'org-a',
        'org-b',
      ])
    })

    it('does NOT fall back to the model when the token asserts none', async () => {
      // The whole point: a deployment that delegated this never fills the local model, so falling
      // back would answer with something the person cannot act on and cannot get changed.
      await expect(callerOrganisations(request([]))).resolves.toEqual([])
    })

    it('does NOT fall back when there is no claim at all', async () => {
      await expect(callerOrganisations(request(undefined))).resolves.toEqual([])
    })

    it('answers nothing for a caller with no context, without reaching for the model', async () => {
      await expect(callerOrganisations({} as FastifyRequest, 'someone@strada.eu')).resolves.toEqual([])
    })

    it('hands back a copy, so a caller cannot edit what the token said', async () => {
      const carried = ['org-a']
      const answered = await callerOrganisations(request(carried))
      answered.push('org-forged')
      expect(carried).toEqual(['org-a'])
    })

    it('reports its scope as claim, so a client can tell which authority answered', () => {
      expect(callerOrganisationsScope()).toBe('claim')
    })
  })
})
