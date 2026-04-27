import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import { createMockDatabase } from '../../cluster/fixtures/cluster.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  databases: [] as Array<{
    id: string
    type: string
    host: string
    port: number
    username: string
    clusterId: string
  }>,
  serverDatabases: {} as Record<string, { roles: Array<{ username: string; adminUsername: string }>; size: number }>,
}))

// Mock database service
vi.mock('../../../services/database.service.js', () => ({
  databaseService: {
    getDatabases: vi.fn().mockImplementation(async (clusterId?: string, page?: number, pageSize?: number) => {
      let data = mockState.databases
      if (clusterId) {
        data = data.filter((d) => d.clusterId === clusterId)
      }
      return { data, total: data.length }
    }),
    getDatabaseById: vi.fn().mockImplementation(async (id: string) => {
      return mockState.databases.find((d) => d.id === id) || null
    }),
    createDatabase: vi.fn().mockImplementation(async (clusterId: string, data: object) => ({
      id: '507f1f77bcf86cd799439099',
      ...data,
      clusterId,
    })),
    updateDatabase: vi.fn().mockImplementation(async (id: string, data: object) => {
      const db = mockState.databases.find((d) => d.id === id)
      if (!db) throw new Error('Not found')
      return { ...db, ...data }
    }),
    deleteDatabase: vi.fn().mockImplementation(async (id: string) => {
      const db = mockState.databases.find((d) => d.id === id)
      if (!db) throw new Error('Not found')
      return db
    }),
    listDatabasesFromServer: vi.fn().mockImplementation(async () => mockState.serverDatabases),
  },
}))

// Import after mocking
import { DatabaseController } from '../../../controllers/database.controller.js'
import { databaseService } from '../../../services/database.service.js'

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

describe('DatabaseController', () => {
  let controller: DatabaseController

  beforeEach(() => {
    vi.clearAllMocks()

    const db1 = createMockDatabase('507f1f77bcf86cd799439011', { id: '507f1f77bcf86cd799439021' })
    const db2 = createMockDatabase('507f1f77bcf86cd799439011', { id: '507f1f77bcf86cd799439022', type: 'mongodb' })

    mockState.databases = [
      { id: db1.id, type: db1.type, host: db1.host, port: db1.port, username: db1.username, clusterId: db1.clusterId },
      { id: db2.id, type: db2.type, host: db2.host, port: db2.port, username: db2.username, clusterId: db2.clusterId },
    ]
    mockState.serverDatabases = {
      test_db: { roles: [{ username: 'user1', adminUsername: 'admin1' }], size: 1024 },
    }

    controller = new DatabaseController()
  })

  // ===========================================================================
  // getDatabases
  // ===========================================================================
  describe('getDatabases', () => {
    it('should return array when no pagination', async () => {
      const request = createMockRequest({ query: {} })
      const reply = createMockReply()

      await controller.getDatabases(
        request as FastifyRequest<{ Querystring: { clusterId?: string; page?: number; pageSize?: number } }>,
        reply
      )

      expect(Array.isArray(reply._body)).toBe(true)
      expect(reply._body).toHaveLength(2)
    })

    it('should return paginated response when page/pageSize provided', async () => {
      const request = createMockRequest({ query: { page: 1, pageSize: 10 } })
      const reply = createMockReply()

      await controller.getDatabases(
        request as FastifyRequest<{ Querystring: { clusterId?: string; page?: number; pageSize?: number } }>,
        reply
      )

      expect(databaseService.getDatabases).toHaveBeenCalledWith(undefined, 1, 10)
    })

    it('should pass clusterId filter to service', async () => {
      const request = createMockRequest({ query: { clusterId: '507f1f77bcf86cd799439011' } })
      const reply = createMockReply()

      await controller.getDatabases(
        request as FastifyRequest<{ Querystring: { clusterId?: string; page?: number; pageSize?: number } }>,
        reply
      )

      expect(databaseService.getDatabases).toHaveBeenCalledWith('507f1f77bcf86cd799439011', undefined, undefined)
    })
  })

  // ===========================================================================
  // getDatabaseById
  // ===========================================================================
  describe('getDatabaseById', () => {
    it('should return database when found', async () => {
      const request = createMockRequest({ params: { id: '507f1f77bcf86cd799439021' } })
      const reply = createMockReply()

      await controller.getDatabaseById(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._body).toBeDefined()
      expect((reply._body as { id: string }).id).toBe('507f1f77bcf86cd799439021')
    })

    it('should return 404 when database not found', async () => {
      const request = createMockRequest({ params: { id: 'non-existent' } })
      const reply = createMockReply()

      await controller.getDatabaseById(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(404)
      expect((reply._body as { message: string }).message).toBe('Database not found')
    })
  })

  // ===========================================================================
  // createDatabase
  // ===========================================================================
  describe('createDatabase', () => {
    it('should return 201 status', async () => {
      const request = createMockRequest({
        params: { clusterId: '507f1f77bcf86cd799439011' },
        body: { type: 'postgresql', host: 'db.example.com', port: 5432, username: 'admin', password: 'secret' },
      })
      const reply = createMockReply()

      await controller.createDatabase(
        request as FastifyRequest<{ Params: { clusterId: string }; Body: object }>,
        reply
      )

      expect(reply._statusCode).toBe(201)
      expect(reply._body).toBeDefined()
    })

    it('should pass clusterId from params', async () => {
      const dbData = { type: 'postgresql', host: 'db.example.com', port: 5432, username: 'admin', password: 'secret' }
      const request = createMockRequest({
        params: { clusterId: '507f1f77bcf86cd799439011' },
        body: dbData,
      })
      const reply = createMockReply()

      await controller.createDatabase(
        request as FastifyRequest<{ Params: { clusterId: string }; Body: typeof dbData }>,
        reply
      )

      expect(databaseService.createDatabase).toHaveBeenCalledWith('507f1f77bcf86cd799439011', dbData)
    })
  })

  // ===========================================================================
  // updateDatabase
  // ===========================================================================
  describe('updateDatabase', () => {
    it('should call service with correct params', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439021' },
        body: { host: 'new-host.example.com' },
      })
      const reply = createMockReply()

      await controller.updateDatabase(
        request as FastifyRequest<{ Params: { id: string }; Body: { host: string } }>,
        reply
      )

      expect(databaseService.updateDatabase).toHaveBeenCalledWith(
        '507f1f77bcf86cd799439021',
        { host: 'new-host.example.com' }
      )
      expect(reply._body).toBeDefined()
    })
  })

  // ===========================================================================
  // deleteDatabase
  // ===========================================================================
  describe('deleteDatabase', () => {
    it('should call service with correct params', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439021' },
      })
      const reply = createMockReply()

      await controller.deleteDatabase(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(databaseService.deleteDatabase).toHaveBeenCalledWith('507f1f77bcf86cd799439021')
      expect(reply._body).toBeDefined()
    })
  })

  // ===========================================================================
  // listDatabasesFromServer
  // ===========================================================================
  describe('listDatabasesFromServer', () => {
    it('should call service and return result', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439021' },
      })
      const reply = createMockReply()

      await controller.listDatabasesFromServer(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(databaseService.listDatabasesFromServer).toHaveBeenCalledWith('507f1f77bcf86cd799439021')
      expect(reply._body).toEqual(mockState.serverDatabases)
    })
  })
})
