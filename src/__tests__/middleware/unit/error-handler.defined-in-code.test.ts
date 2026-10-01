import { describe, it, expect } from 'vitest'
import Fastify from 'fastify'
import { errorHandler } from '../../../middleware/error-handler.js'
import { SystemResourceImmutable } from '../../../services/rbac.service.js'
import { conflictResponseSchema } from '../../../schemas/response-schemas.js'

// A 409 for something defined in code carries a machine code, so a console tells it apart from a
// 409 "already exists" — through the route's 409 schema too.

describe('error handler — defined_in_code', () => {
  it('answers {error, code: defined_in_code, message}; another 409 keeps its shape', async () => {
    const app = Fastify()
    app.setErrorHandler(errorHandler)
    const schema = { response: { 409: conflictResponseSchema } }
    app.put('/staff', { schema }, async () => { throw new SystemResourceImmutable('group', 'staff-ops') })
    app.put('/roles', { schema }, async () => { throw Object.assign(new Error("The roles of 'jinbe' are defined in code"), { statusCode: 409, code: 'defined_in_code' }) })
    app.put('/dup', { schema }, async () => { throw Object.assign(new Error('Group already exists'), { statusCode: 409 }) })
    expect((await app.inject({ method: 'PUT', url: '/staff' })).json()).toEqual({ error: 'defined_in_code', code: 'defined_in_code', message: "The group 'staff-ops' is defined in code and cannot be changed here" })
    expect((await app.inject({ method: 'PUT', url: '/roles' })).json()).toMatchObject({ code: 'defined_in_code' })
    const dup = await app.inject({ method: 'PUT', url: '/dup' })
    expect(dup.statusCode).toBe(409)
    expect(dup.json()).toEqual({ error: 'Group already exists' })
    await app.close()
  })
})
