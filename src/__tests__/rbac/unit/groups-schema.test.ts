import { describe, it, expect } from 'vitest'
import Fastify from 'fastify'
import { groupJsonSchema } from '../../../schemas/rbac/groups.schema.js'

// GET /api/admin/rbac/groups serializes through groupJsonSchema: a console marks a group defined in
// code (system) before a write meets 409 defined_in_code, so the flag and its label must survive it.

describe('groupJsonSchema', () => {
  it('keeps system and description through the response serializer', async () => {
    const app = Fastify()
    app.get('/g', { schema: { response: { 200: { type: 'object', properties: { groups: { type: 'array', items: groupJsonSchema } } } } } },
      async () => ({ groups: [{ name: 'staff-ops', services: { jinbe: ['ops'] }, system: true, description: 'Operations', internal: 'x' }] }))
    const res = await app.inject({ url: '/g' })
    expect(res.json().groups[0]).toEqual({ name: 'staff-ops', services: { jinbe: ['ops'] }, system: true, description: 'Operations' })
    await app.close()
  })
})
