import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

// ---------------------------------------------------------------------------
// Mocks — the SCIM routes call scimService for all resource work, the token
// service (via scimAuth) for authentication, and the audit service on writes.
// ---------------------------------------------------------------------------
const mocks = vi.hoisted(() => ({
  listUsers: vi.fn(),
  getUser: vi.fn(),
  createUser: vi.fn(),
  replaceUser: vi.fn(),
  patchUser: vi.fn(),
  deactivateUser: vi.fn(),
  verify: vi.fn(),
  auditEmit: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('../../../services/scim.service.js', async (importActual) => {
  const actual = await importActual<typeof import('../../../services/scim.service.js')>()
  return {
    ...actual,
    scimService: {
      listUsers: mocks.listUsers,
      getUser: mocks.getUser,
      createUser: mocks.createUser,
      replaceUser: mocks.replaceUser,
      patchUser: mocks.patchUser,
      deactivateUser: mocks.deactivateUser,
    },
  }
})
vi.mock('../../../services/scim-token.service.js', () => ({
  scimTokenService: { verify: mocks.verify },
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: mocks.auditEmit },
}))

import { scimRoutes } from '../../../routes/scim.routes.js'
import { ScimError } from '../../../services/scim.service.js'

type Handler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>

function createMockFastify() {
  const routes: Array<{ method: string; path: string; handler: Handler }> = []
  const hooks: Array<{ name: string; fn: Handler }> = []
  const record =
    (method: string) =>
    (path: string, a?: unknown, b?: unknown) => {
      const handler = (typeof a === 'function' ? a : b) as Handler
      routes.push({ method, path, handler })
    }
  return {
    registeredRoutes: routes,
    registeredHooks: hooks,
    get: vi.fn(record('GET')),
    post: vi.fn(record('POST')),
    put: vi.fn(record('PUT')),
    delete: vi.fn(record('DELETE')),
    patch: vi.fn(record('PATCH')),
    addHook: vi.fn((name: string, fn: Handler) => hooks.push({ name, fn })),
    addContentTypeParser: vi.fn(),
  } as unknown as FastifyInstance & {
    registeredRoutes: Array<{ method: string; path: string; handler: Handler }>
    registeredHooks: Array<{ name: string; fn: Handler }>
  }
}

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

function createRequest(overrides: Record<string, unknown> = {}) {
  return {
    headers: { authorization: 'Bearer scim_ok', 'user-agent': 'idp' },
    method: 'GET',
    url: '/scim/v2/Users',
    ip: '10.0.0.1',
    id: 'req-1',
    scimToken: { tokenId: 'tok1', label: 'entra' },
    query: {},
    params: {},
    body: {},
    ...overrides,
  } as unknown as FastifyRequest
}

describe('scimRoutes', () => {
  let fastify: ReturnType<typeof createMockFastify>

  const handlerFor = (method: string, path: string): Handler => {
    const route = fastify.registeredRoutes.find((r) => r.method === method && r.path === path)
    if (!route) throw new Error(`No ${method} handler registered for ${path}`)
    return route.handler
  }

  beforeEach(async () => {
    vi.clearAllMocks()
    fastify = createMockFastify()
    await scimRoutes(fastify)
  })

  it('registers the bearer auth as an onRequest hook (before parsing/validation)', () => {
    const authHooks = fastify.registeredHooks.filter((h) => h.name === 'onRequest')
    expect(authHooks).toHaveLength(1)
  })

  it('registers a parser for application/scim+json', () => {
    expect(fastify.addContentTypeParser).toHaveBeenCalledWith(
      'application/scim+json',
      { parseAs: 'string' },
      expect.any(Function)
    )
  })

  it('the auth hook 401s requests without a valid token (fail-closed)', async () => {
    mocks.verify.mockResolvedValue(null)
    const hook = fastify.registeredHooks.find((h) => h.name === 'onRequest')!.fn
    const reply = createMockReply()
    await hook(createRequest({ scimToken: undefined, headers: {} }), reply)
    expect(reply._status).toBe(401)
    expect(reply._body.schemas).toEqual(['urn:ietf:params:scim:api:messages:2.0:Error'])
    expect(reply._body.status).toBe('401')
  })

  describe('discovery endpoints', () => {
    it('GET /ServiceProviderConfig declares exactly what phase 1 implements', async () => {
      const reply = createMockReply()
      const spc = (await handlerFor('GET', '/ServiceProviderConfig')(createRequest(), reply)) as any
      expect(spc.schemas).toEqual(['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'])
      expect(spc.patch).toEqual({ supported: true })
      expect(spc.filter).toEqual({ supported: true, maxResults: 200 })
      expect(spc.bulk.supported).toBe(false)
      expect(spc.sort.supported).toBe(false)
      expect(spc.etag.supported).toBe(false)
      expect(spc.changePassword.supported).toBe(false)
      expect(spc.authenticationSchemes[0].type).toBe('oauthbearertoken')
      expect(reply._headers['Content-Type']).toBe('application/scim+json')
    })

    it('GET /ResourceTypes lists only User (phase 1)', async () => {
      const body = (await handlerFor('GET', '/ResourceTypes')(createRequest(), createMockReply())) as any
      expect(body.schemas).toEqual(['urn:ietf:params:scim:api:messages:2.0:ListResponse'])
      expect(body.totalResults).toBe(1)
      expect(body.Resources[0]).toMatchObject({
        id: 'User',
        endpoint: '/Users',
        schema: 'urn:ietf:params:scim:schemas:core:2.0:User',
      })
    })

    it('GET /Schemas returns the User schema definition', async () => {
      const body = (await handlerFor('GET', '/Schemas')(createRequest(), createMockReply())) as any
      expect(body.Resources[0].id).toBe('urn:ietf:params:scim:schemas:core:2.0:User')
      const attrs = body.Resources[0].attributes.map((a: any) => a.name)
      expect(attrs).toContain('userName')
      expect(attrs).toContain('active')
    })
  })

  describe('GET /Users', () => {
    it('returns an RFC 7644 ListResponse', async () => {
      mocks.listUsers.mockResolvedValue({
        totalResults: 1,
        startIndex: 1,
        itemsPerPage: 1,
        resources: [{ userName: 'a@x.dev' }],
      })
      const request = createRequest({ query: { filter: 'userName eq "a@x.dev"' } })
      const body = (await handlerFor('GET', '/Users')(request, createMockReply())) as any
      expect(mocks.listUsers).toHaveBeenCalledWith({ filter: 'userName eq "a@x.dev"' })
      expect(body).toEqual({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
        totalResults: 1,
        startIndex: 1,
        itemsPerPage: 1,
        Resources: [{ userName: 'a@x.dev' }],
      })
    })

    it('maps an unsupported filter to a 501 SCIM error', async () => {
      mocks.listUsers.mockRejectedValue(new ScimError(501, 'Unsupported filter'))
      const reply = createMockReply()
      await handlerFor('GET', '/Users')(createRequest(), reply)
      expect(reply._status).toBe(501)
      expect(reply._body.schemas).toEqual(['urn:ietf:params:scim:api:messages:2.0:Error'])
    })
  })

  describe('POST /Users', () => {
    it('creates, returns 201 with Location, and audits the write', async () => {
      mocks.createUser.mockResolvedValue({ id: 'uid-1', userName: 'a@x.dev' })
      const reply = createMockReply()
      await handlerFor('POST', '/Users')(createRequest({ body: { userName: 'a@x.dev' } }), reply)
      expect(mocks.createUser).toHaveBeenCalledWith({ userName: 'a@x.dev' }, 'tok1')
      expect(reply._status).toBe(201)
      expect(reply._headers.Location).toBe('/scim/v2/Users/uid-1')
      expect(reply._body).toEqual({ id: 'uid-1', userName: 'a@x.dev' })
      expect(mocks.auditEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          verb: 'create',
          target: 'user:a@x.dev',
          source: 'scim',
          actor: expect.objectContaining({ email: 'scim:entra' }),
        })
      )
    })

    it('maps a duplicate email to 409 uniqueness', async () => {
      mocks.createUser.mockRejectedValue(new ScimError(409, 'exists', 'uniqueness'))
      const reply = createMockReply()
      await handlerFor('POST', '/Users')(createRequest({ body: { userName: 'a@x.dev' } }), reply)
      expect(reply._status).toBe(409)
      expect(reply._body).toMatchObject({ scimType: 'uniqueness', status: '409' })
      expect(mocks.auditEmit).not.toHaveBeenCalled()
    })
  })

  describe('GET/PUT/PATCH/DELETE /Users/:id', () => {
    it('GET returns the resource; 404 becomes a SCIM error', async () => {
      mocks.getUser.mockResolvedValue({ id: 'uid-1' })
      const ok = (await handlerFor('GET', '/Users/:id')(
        createRequest({ params: { id: 'uid-1' } }),
        createMockReply()
      )) as any
      expect(ok).toEqual({ id: 'uid-1' })

      mocks.getUser.mockRejectedValue(new ScimError(404, 'not found'))
      const reply = createMockReply()
      await handlerFor('GET', '/Users/:id')(createRequest({ params: { id: 'missing' } }), reply)
      expect(reply._status).toBe(404)
      expect(reply._body.status).toBe('404')
    })

    it('PUT replaces and audits', async () => {
      mocks.replaceUser.mockResolvedValue({ id: 'uid-1', userName: 'a@x.dev' })
      const request = createRequest({ params: { id: 'uid-1' }, body: { userName: 'a@x.dev' } })
      await handlerFor('PUT', '/Users/:id')(request, createMockReply())
      expect(mocks.replaceUser).toHaveBeenCalledWith('uid-1', { userName: 'a@x.dev' }, 'tok1')
      expect(mocks.auditEmit).toHaveBeenCalledWith(expect.objectContaining({ verb: 'update' }))
    })

    it('PATCH forwards the PatchOp body and audits', async () => {
      mocks.patchUser.mockResolvedValue({ id: 'uid-1', userName: 'a@x.dev', active: false })
      const body = { Operations: [{ op: 'replace', path: 'active', value: false }] }
      const request = createRequest({ params: { id: 'uid-1' }, body })
      await handlerFor('PATCH', '/Users/:id')(request, createMockReply())
      expect(mocks.patchUser).toHaveBeenCalledWith('uid-1', body, 'tok1')
      expect(mocks.auditEmit).toHaveBeenCalledWith(
        expect.objectContaining({ verb: 'update', details: expect.objectContaining({ op: 'patch', active: false }) })
      )
    })

    it('DELETE soft-deactivates, returns 204, and audits', async () => {
      mocks.deactivateUser.mockResolvedValue(undefined)
      const reply = createMockReply()
      await handlerFor('DELETE', '/Users/:id')(createRequest({ params: { id: 'uid-1' } }), reply)
      expect(mocks.deactivateUser).toHaveBeenCalledWith('uid-1', 'tok1')
      expect(reply._status).toBe(204)
      expect(mocks.auditEmit).toHaveBeenCalledWith(
        expect.objectContaining({ verb: 'delete', details: expect.objectContaining({ softDelete: true }) })
      )
    })
  })
})
