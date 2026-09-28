import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { FastifyRequest } from 'fastify'

// Audit pages name people by id; who they are is resolved when read, for a caller who could look
// them up anyway, and never written into the events.

const h = vi.hoisted(() => ({
  permissions: ['users:read'] as string[],
  identities: new Map<string, { id: string; traits: Record<string, unknown> }>(),
  kratosDown: false,
}))
vi.mock('../../../authz/opa.js', () => ({ rights: vi.fn(async () => ({ groups: [], roles: [], permissions: h.permissions })) }))
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getIdentitiesByIds: vi.fn(async (ids: string[]) => {
      if (h.kratosDown) throw new Error('kratos down')
      return new Map(ids.filter((id) => h.identities.has(id)).map((id) => [id, h.identities.get(id)!]))
    }),
  },
}))

import { actorDirectory, userActorIds } from '../../../audit/query/actors.js'

const A = 'c1a5623e-5c44-4a4b-9f0e-000000000001'
const B = 'c1a5623e-5c44-4a4b-9f0e-000000000002'
const request = (email = 'admin@x.test') =>
  ({ userContext: { email }, log: { warn: vi.fn() } }) as unknown as FastifyRequest

beforeEach(() => {
  h.permissions = ['users:read']
  h.kratosDown = false
  h.identities = new Map([[A, { id: A, traits: { email: 'maxime@x.test', name: 'Maxime' } }]])
})

describe('userActorIds', () => {
  it('keeps distinct user identity ids only', () => {
    const events = [
      { actor: { type: 'user', id: A } }, { actor: { type: 'user', id: A.toUpperCase() } },
      { actor: { type: 'service', id: 'kratos' } }, { actor: { type: 'anonymous', id: null } }, { actor: { type: 'user', id: 'not-an-id' } },
    ]
    expect(userActorIds(events, [B, 'jinbe'])).toEqual([A, B])
  })
})

describe('actorDirectory', () => {
  it('names each user actor, and says null for a deleted identity', async () => {
    expect(await actorDirectory(request(), [A, B])).toEqual({ [A]: { email: 'maxime@x.test', name: 'Maxime' }, [B]: null })
  })

  it('is left out for a caller who may not look people up', async () => {
    h.permissions = ['audit:read']
    expect(await actorDirectory(request(), [A])).toBeUndefined()
  })

  it('is left out when Kratos cannot answer — the page shows ids instead of failing', async () => {
    h.kratosDown = true
    expect(await actorDirectory(request(), [A])).toBeUndefined()
  })

  it('asks nothing for a page with no user actors', async () => {
    expect(await actorDirectory(request(), [])).toBeUndefined()
  })
})
