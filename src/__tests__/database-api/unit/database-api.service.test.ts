import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  createMockDatabase,
  createMockDatabaseAPI,
  MockDatabaseAPI,
} from '../../cluster/fixtures/cluster.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  databaseAPIs: [] as (MockDatabaseAPI & { database?: { id: string; type: string; host: string; port: number } })[],
}))

// Mock Prisma
vi.mock('../../../utils/prisma.js', () => ({
  prisma: {
    databaseAPI: {
      findMany: vi.fn().mockImplementation(async () => mockState.databaseAPIs),
      findUnique: vi.fn().mockImplementation(async ({ where }: { where: { id?: string; databaseId?: string } }) => {
        if (where.id) {
          return mockState.databaseAPIs.find((api) => api.id === where.id) || null
        }
        if (where.databaseId) {
          return mockState.databaseAPIs.find((api) => api.databaseId === where.databaseId) || null
        }
        return null
      }),
      create: vi.fn().mockImplementation(async ({ data }: { data: { address: string; api_key: string; databaseId: string } }) => {
        const newApi: MockDatabaseAPI & { database?: { id: string; type: string; host: string; port: number } } = {
          id: '507f1f77bcf86cd799439099',
          address: data.address,
          api_key: data.api_key,
          databaseId: data.databaseId,
          database: { id: data.databaseId, type: 'postgresql', host: 'localhost', port: 5432 },
        }
        mockState.databaseAPIs.push(newApi)
        return newApi
      }),
      update: vi.fn().mockImplementation(async ({ where, data }: { where: { id: string }; data: { address?: string; api_key?: string } }) => {
        const api = mockState.databaseAPIs.find((a) => a.id === where.id)
        if (!api) throw new Error('DatabaseAPI not found')
        if (data.address) api.address = data.address
        if (data.api_key) api.api_key = data.api_key
        return api
      }),
      delete: vi.fn().mockImplementation(async ({ where }: { where: { id: string } }) => {
        const index = mockState.databaseAPIs.findIndex((a) => a.id === where.id)
        if (index === -1) throw new Error('DatabaseAPI not found')
        const [deleted] = mockState.databaseAPIs.splice(index, 1)
        return deleted
      }),
    },
  },
}))

// Import after mocking
import { DatabaseAPIService } from '../../../services/database-api.service.js'
import { prisma } from '../../../utils/prisma.js'

describe('DatabaseAPIService', () => {
  let service: DatabaseAPIService

  beforeEach(() => {
    vi.clearAllMocks()

    const db1 = createMockDatabase('507f1f77bcf86cd799439011', { id: '507f1f77bcf86cd799439021' })
    const db2 = createMockDatabase('507f1f77bcf86cd799439011', { id: '507f1f77bcf86cd799439022', type: 'mongodb', port: 27017 })

    const api1 = createMockDatabaseAPI(db1.id, { id: '507f1f77bcf86cd799439031' })
    const api2 = createMockDatabaseAPI(db2.id, { id: '507f1f77bcf86cd799439032', address: 'http://mongo-api.example.com' })

    mockState.databaseAPIs = [
      { ...api1, database: { id: db1.id, type: db1.type, host: db1.host, port: db1.port } },
      { ...api2, database: { id: db2.id, type: db2.type, host: db2.host, port: db2.port } },
    ]

    service = new DatabaseAPIService()
  })

  // ===========================================================================
  // getDatabaseAPIs
  // ===========================================================================
  describe('getDatabaseAPIs', () => {
    it('should return all database APIs', async () => {
      const result = await service.getDatabaseAPIs()

      expect(result).toHaveLength(2)
    })

    it('should include database relation', async () => {
      await service.getDatabaseAPIs()

      expect(prisma.databaseAPI.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          include: expect.objectContaining({
            database: expect.any(Object),
          }),
        })
      )
    })
  })

  // ===========================================================================
  // getDatabaseAPIById
  // ===========================================================================
  describe('getDatabaseAPIById', () => {
    it('should return API by ID', async () => {
      const result = await service.getDatabaseAPIById('507f1f77bcf86cd799439031')

      expect(result).not.toBeNull()
      expect(result?.id).toBe('507f1f77bcf86cd799439031')
    })

    it('should return null when not found', async () => {
      const result = await service.getDatabaseAPIById('non-existent-id')

      expect(result).toBeNull()
    })

    it('should include database relation', async () => {
      await service.getDatabaseAPIById('507f1f77bcf86cd799439031')

      expect(prisma.databaseAPI.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          include: expect.objectContaining({
            database: expect.any(Object),
          }),
        })
      )
    })
  })

  // ===========================================================================
  // getDatabaseAPIByDatabaseId
  // ===========================================================================
  describe('getDatabaseAPIByDatabaseId', () => {
    it('should return API by database ID', async () => {
      const result = await service.getDatabaseAPIByDatabaseId('507f1f77bcf86cd799439021')

      expect(result).not.toBeNull()
      expect(result?.databaseId).toBe('507f1f77bcf86cd799439021')
    })

    it('should return null when not found', async () => {
      const result = await service.getDatabaseAPIByDatabaseId('non-existent-db-id')

      expect(result).toBeNull()
    })

    it('should include database relation', async () => {
      await service.getDatabaseAPIByDatabaseId('507f1f77bcf86cd799439021')

      expect(prisma.databaseAPI.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { databaseId: '507f1f77bcf86cd799439021' },
          include: expect.objectContaining({
            database: expect.any(Object),
          }),
        })
      )
    })
  })

  // ===========================================================================
  // createDatabaseAPI
  // ===========================================================================
  describe('createDatabaseAPI', () => {
    it('should create API with address and api_key', async () => {
      const result = await service.createDatabaseAPI('507f1f77bcf86cd799439023', {
        address: 'http://new-api.example.com',
        api_key: 'new-key-123',
      })

      expect(result.address).toBe('http://new-api.example.com')
      expect(result.api_key).toBe('new-key-123')
    })

    it('should link to database', async () => {
      await service.createDatabaseAPI('507f1f77bcf86cd799439023', {
        address: 'http://new-api.example.com',
        api_key: 'new-key-123',
      })

      expect(prisma.databaseAPI.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            databaseId: '507f1f77bcf86cd799439023',
          }),
        })
      )
    })

    it('should include database relation in response', async () => {
      await service.createDatabaseAPI('507f1f77bcf86cd799439023', {
        address: 'http://new-api.example.com',
        api_key: 'new-key-123',
      })

      expect(prisma.databaseAPI.create).toHaveBeenCalledWith(
        expect.objectContaining({
          include: expect.objectContaining({
            database: expect.any(Object),
          }),
        })
      )
    })
  })

  // ===========================================================================
  // updateDatabaseAPI
  // ===========================================================================
  describe('updateDatabaseAPI', () => {
    it('should update address', async () => {
      const result = await service.updateDatabaseAPI('507f1f77bcf86cd799439031', {
        address: 'http://updated-api.example.com',
      })

      expect(result.address).toBe('http://updated-api.example.com')
    })

    it('should update api_key', async () => {
      const result = await service.updateDatabaseAPI('507f1f77bcf86cd799439031', {
        api_key: 'updated-key',
      })

      expect(result.api_key).toBe('updated-key')
    })

    it('should call prisma with correct params', async () => {
      await service.updateDatabaseAPI('507f1f77bcf86cd799439031', {
        address: 'http://updated.com',
        api_key: 'new-key',
      })

      expect(prisma.databaseAPI.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: '507f1f77bcf86cd799439031' },
          data: expect.objectContaining({
            address: 'http://updated.com',
            api_key: 'new-key',
          }),
        })
      )
    })
  })

  // ===========================================================================
  // deleteDatabaseAPI
  // ===========================================================================
  describe('deleteDatabaseAPI', () => {
    it('should delete and return deleted record', async () => {
      const result = await service.deleteDatabaseAPI('507f1f77bcf86cd799439031')

      expect(result.id).toBe('507f1f77bcf86cd799439031')
      expect(mockState.databaseAPIs).toHaveLength(1)
    })

    it('should call prisma with correct params', async () => {
      await service.deleteDatabaseAPI('507f1f77bcf86cd799439031')

      expect(prisma.databaseAPI.delete).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: '507f1f77bcf86cd799439031' },
        })
      )
    })
  })
})
