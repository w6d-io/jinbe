import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

const mocks = vi.hoisted(() => ({
  verify: vi.fn(),
  auditEmit: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('../../../services/scim-token.service.js', () => ({
  scimTokenService: { verify: mocks.verify },
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: mocks.auditEmit },
}))

import { scimAuth, scimErrorBody } from '../../../middleware/scim-auth.js'

function createMockReply() {
  const reply = {
    _status: 200,
    _body: undefined as unknown,
    _headers: {} as Record<string, string>,
    status: vi.fn(function (this: any, s: number) { this._status = s; return this }),
    header: vi.fn(function (this: any, k: string, v: string) { this._headers[k] = v; return this }),
    send: vi.fn(function (this: any, b: unknown) { this._body = b; return this }),
  }
  return reply as unknown as FastifyReply & { _status: number; _body: any; _headers: Record<string, string> }
}

function createMockRequest(authorization?: string) {
  return {
    headers: { authorization, 'user-agent': 'entra' },
    method: 'GET',
    url: '/scim/v2/Users',
    ip: '10.0.0.1',
  } as unknown as FastifyRequest
}

describe('scimAuth middleware', () => {
  beforeEach(() => vi.clearAllMocks())

  it('401s with an RFC 7644 error body when no token is presented', async () => {
    const reply = createMockReply()
    await scimAuth(createMockRequest(undefined), reply)
    expect(reply._status).toBe(401)
    expect(reply._headers['WWW-Authenticate']).toBe('Bearer realm="scim"')
    expect(reply._headers['Content-Type']).toBe('application/scim+json')
    expect(reply._body).toEqual({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      detail: 'Valid SCIM bearer token required.',
      status: '401',
    })
    expect(mocks.verify).not.toHaveBeenCalled()
    expect(mocks.auditEmit).toHaveBeenCalledWith(
      expect.objectContaining({ verb: 'deny', reason: 'scim_token_missing', source: 'scim' })
    )
  })

  it('401s when the token is invalid (fail-closed)', async () => {
    mocks.verify.mockResolvedValue(null)
    const reply = createMockReply()
    await scimAuth(createMockRequest('Bearer scim_bad_token'), reply)
    expect(mocks.verify).toHaveBeenCalledWith('scim_bad_token')
    expect(reply._status).toBe(401)
    expect(reply._body.schemas).toEqual(['urn:ietf:params:scim:api:messages:2.0:Error'])
    expect(mocks.auditEmit).toHaveBeenCalledWith(
      expect.objectContaining({ reason: 'scim_token_invalid' })
    )
  })

  it('attaches the principal on a valid token and does not reply', async () => {
    mocks.verify.mockResolvedValue({ tokenId: 'tok1', label: 'entra' })
    const request = createMockRequest('Bearer scim_good')
    const reply = createMockReply()
    await scimAuth(request, reply)
    expect((request as any).scimToken).toEqual({ tokenId: 'tok1', label: 'entra' })
    expect(reply.send).not.toHaveBeenCalled()
    expect(mocks.auditEmit).not.toHaveBeenCalled()
  })

  it('rejects non-Bearer authorization schemes', async () => {
    const reply = createMockReply()
    await scimAuth(createMockRequest('Basic dXNlcjpwYXNz'), reply)
    expect(reply._status).toBe(401)
    expect(mocks.verify).not.toHaveBeenCalled()
  })

  it('scimErrorBody renders status as a string per RFC 7644', () => {
    expect(scimErrorBody(409, 'dup', 'uniqueness')).toEqual({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      scimType: 'uniqueness',
      detail: 'dup',
      status: '409',
    })
  })
})
