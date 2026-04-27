import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import { createMockDatabaseAPI } from '../../cluster/fixtures/cluster.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  databaseAPIs: [] as Array<{
    id: string
    address: string
    api_key: string
    databaseId: string
    database?: { id: string; type: string; host: string; port: number }
  }>,
}))

// Mock database-api service
vi.mock('../../../services/database-api.service.js', () => ({
  databaseAPIService: {
    getDatabaseAPIs: vi.fn().mockImplementation(async () => mockState.databaseAPIs),
    getDatabaseAPIById: vi.fn().mockImplementation(async (id: string) => {
      return mockState.databaseAPIs.find((api) => api.id === id) || null
    }),
    getDatabaseAPIByDatabaseId: vi.fn().mockImplementation(async (databaseId: string) => {
      return mockState.databaseAPIs.find((api) => api.databaseId === databaseId) || null
    }),
    createDatabaseAPI: vi.fn().mockImplementation(async (databaseId: string, data: { address: string; api_key: string }) => ({
      id: '507f1f77bcf86cd799439099',
      address: data.address,
      api_key: data.api_key,
      databaseId,
      database: { id: databaseId, type: 'postgresql', host: 'localhost', port: 5432 },
    })),
    updateDatabaseAPI: vi.fn().mockImplementation(async (id: string, data: object) => {
      const api = mockState.databaseAPIs.find((a) => a.id === id)
      if (!api) throw new Error('Not found')
      return { ...api, ...data }
    }),
    deleteDatabaseAPI: vi.fn().mockImplementation(async (id: string) => {
      const api = mockState.databaseAPIs.find((a) => a.id === id)
      if (!api) throw new Error('Not found')
      return api
    }),
  },
}))

// Import after mocking
import { DatabaseAPIController } from '../../../controllers/database-api.controller.js'
import { databaseAPIService } from '../../../services/database-api.service.js'

// Helper to create mock request
function createMockRequest<T extends object = object>(
  overrides: Partial<FastifyRequest> & T = {} as T
): FastifyRequest & T {
  return {
    query: {},
    params: {},
    body: {},
    ...overrides,
  } as FastifyRequest & T
}

// Helper to create mock reply
function createMockReply(): FastifyReply & { _statusCode?: number; _body?: unknown } {
  const reply = {
    _statusCode: 200 as number | undefined,
    _body: undefined as unknown,
    status: vi.fn().mockImplementation(function (this: typeof reply, code: number) {
      this._statusCode = code
      return this
    }),
    send: vi.fn().mockImplementation(function (this: typeof reply, body: unknown) {
      this._body = body
      return this
    }),
  }
  return reply as unknown as FastifyReply & { _statusCode?: number; _body?: unknown }
}

describe('DatabaseAPIController', () => {
  let controller: DatabaseAPIController

  beforeEach(() => {
    vi.clearAllMocks()

    const api1 = createMockDatabaseAPI('507f1f77bcf86cd799439021', { id: '507f1f77bcf86cd799439031' })
    const api2 = createMockDatabaseAPI('507f1f77bcf86cd799439022', { id: '507f1f77bcf86cd799439032' })

    mockState.databaseAPIs = [
      { ...api1, database: { id: '507f1f77bcf86cd799439021', type: 'postgresql', host: 'localhost', port: 5432 } },
      { ...api2, database: { id: '507f1f77bcf86cd799439022', type: 'mongodb', host: 'localhost', port: 27017 } },
    ]

    controller = new DatabaseAPIController()
  })

  // ===========================================================================
  // getDatabaseAPIs
  // ===========================================================================
  describe('getDatabaseAPIs', () => {
    it('should return all database APIs', async () => {
      const request = createMockRequest({})
      const reply = createMockReply()

      await controller.getDatabaseAPIs(request, reply)

      expect(databaseAPIService.getDatabaseAPIs).toHaveBeenCalled()
      expect(reply._body).toHaveLength(2)
    })
  })

  // ===========================================================================
  // getDatabaseAPIById
  // ===========================================================================
  describe('getDatabaseAPIById', () => {
    it('should return API when found', async () => {
      const request = createMockRequest({ params: { id: '507f1f77bcf86cd799439031' } })
      const reply = createMockReply()

      await controller.getDatabaseAPIById(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._body).toBeDefined()
      expect((reply._body as { id: string }).id).toBe('507f1f77bcf86cd799439031')
    })

    it('should return 404 when not found', async () => {
      const request = createMockRequest({ params: { id: 'non-existent' } })
      const reply = createMockReply()

      await controller.getDatabaseAPIById(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(404)
      expect((reply._body as { message: string }).message).toBe('Database API not found')
    })
  })

  // ===========================================================================
  // getDatabaseAPIByDatabaseId
  // ===========================================================================
  describe('getDatabaseAPIByDatabaseId', () => {
    it('should return API when found', async () => {
      const request = createMockRequest({ params: { databaseId: '507f1f77bcf86cd799439021' } })
      const reply = createMockReply()

      await controller.getDatabaseAPIByDatabaseId(
        request as FastifyRequest<{ Params: { databaseId: string } }>,
        reply
      )

      expect(reply._body).toBeDefined()
      expect((reply._body as { databaseId: string }).databaseId).toBe('507f1f77bcf86cd799439021')
    })

    it('should return 404 when not found', async () => {
      const request = createMockRequest({ params: { databaseId: 'non-existent' } })
      const reply = createMockReply()

      await controller.getDatabaseAPIByDatabaseId(
        request as FastifyRequest<{ Params: { databaseId: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(404)
      expect((reply._body as { message: string }).message).toBe('Database API not found for this database')
    })
  })

  // ===========================================================================
  // createDatabaseAPI
  // ===========================================================================
  describe('createDatabaseAPI', () => {
    it('should return 201 status', async () => {
      const request = createMockRequest({
        params: { databaseId: '507f1f77bcf86cd799439023' },
        body: { address: 'http://new-api.example.com', api_key: 'key-123' },
      })
      const reply = createMockReply()

      await controller.createDatabaseAPI(
        request as FastifyRequest<{ Params: { databaseId: string }; Body: { address: string; api_key: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(201)
      expect(reply._body).toBeDefined()
    })

    it('should call service with correct params', async () => {
      const apiData = { address: 'http://new-api.example.com', api_key: 'key-123' }
      const request = createMockRequest({
        params: { databaseId: '507f1f77bcf86cd799439023' },
        body: apiData,
      })
      const reply = createMockReply()

      await controller.createDatabaseAPI(
        request as FastifyRequest<{ Params: { databaseId: string }; Body: typeof apiData }>,
        reply
      )

      expect(databaseAPIService.createDatabaseAPI).toHaveBeenCalledWith('507f1f77bcf86cd799439023', apiData)
    })
  })

  // ===========================================================================
  // updateDatabaseAPI
  // ===========================================================================
  describe('updateDatabaseAPI', () => {
    it('should return 200 status', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439031' },
        body: { address: 'http://updated.example.com' },
      })
      const reply = createMockReply()

      await controller.updateDatabaseAPI(
        request as FastifyRequest<{ Params: { id: string }; Body: { address: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(200)
      expect(reply._body).toBeDefined()
    })

    it('should call service with correct params', async () => {
      const updateData = { address: 'http://updated.example.com', api_key: 'new-key' }
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439031' },
        body: updateData,
      })
      const reply = createMockReply()

      await controller.updateDatabaseAPI(
        request as FastifyRequest<{ Params: { id: string }; Body: typeof updateData }>,
        reply
      )

      expect(databaseAPIService.updateDatabaseAPI).toHaveBeenCalledWith('507f1f77bcf86cd799439031', updateData)
    })
  })

  // ===========================================================================
  // deleteDatabaseAPI
  // ===========================================================================
  describe('deleteDatabaseAPI', () => {
    it('should return 200 status', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439031' },
      })
      const reply = createMockReply()

      await controller.deleteDatabaseAPI(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(200)
      expect(reply._body).toBeDefined()
    })

    it('should call service with correct params', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439031' },
      })
      const reply = createMockReply()

      await controller.deleteDatabaseAPI(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(databaseAPIService.deleteDatabaseAPI).toHaveBeenCalledWith('507f1f77bcf86cd799439031')
    })
  })
})
