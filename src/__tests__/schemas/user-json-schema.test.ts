import { describe, it, expect } from 'vitest'
import Fastify from 'fastify'
import { userCreateJsonSchema, userUpdateJsonSchema } from '../../schemas/admin.schema.js'

// The Kratos identity schema stores `name` as a plain string; the body schemas must accept what
// Kratos stores, or no name can ever be saved.
async function accepts(schema: object, body: object) {
  const app = Fastify()
  app.post('/', { schema: { body: schema } }, async () => ({ ok: true }))
  const res = await app.inject({ method: 'POST', url: '/', payload: body })
  await app.close()
  return res.statusCode
}

describe('user body schemas — name', () => {
  it('update accepts a string name', async () => {
    expect(await accepts(userUpdateJsonSchema, { traits: { name: 'Jane Doe' } })).toBe(200)
  })

  it('create accepts a string name', async () => {
    expect(await accepts(userCreateJsonSchema, { traits: { email: 'jane@x.io', name: 'Jane Doe' } })).toBe(200)
  })

  it('update refuses an object name Kratos would reject', async () => {
    expect(await accepts(userUpdateJsonSchema, { traits: { name: { first: 'J', last: 'D' } } })).toBe(400)
  })
})
