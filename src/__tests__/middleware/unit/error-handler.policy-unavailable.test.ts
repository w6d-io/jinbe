import Fastify from 'fastify'
import { describe, expect, it } from 'vitest'
import { POLICY_UNAVAILABLE } from '../../../authz/policy-unavailable.js'
import { errorHandler } from '../../../middleware/error-handler.js'

async function answer(err: Error) {
  const app = Fastify()
  app.setErrorHandler(errorHandler)
  app.get('/x', async () => { throw err })
  return app.inject({ url: '/x' })
}

describe('error handler: OPA could not be asked', () => {
  it('a thrown policy_unavailable error answers 503 with the code and keeps the message', async () => {
    const res = await answer(Object.assign(new Error('OPA could not be asked, so nobody may do y: down'), { statusCode: 503, code: POLICY_UNAVAILABLE }))
    expect(res.statusCode).toBe(503)
    expect(res.json()).toEqual({ error: 'policy_unavailable', message: 'OPA could not be asked, so nobody may do y: down' })
  })

  it('other status errors keep their shape', async () => {
    const res = await answer(Object.assign(new Error('Only admin.membership:write may do y'), { statusCode: 403 }))
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ error: 'Only admin.membership:write may do y' })
  })
})
