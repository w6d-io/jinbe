import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  createMockDatabase,
  createMockDatabaseAPI,
  MockDatabase,
  MockDatabaseAPI,
} from '../../cluster/fixtures/cluster.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  databases: [] as (MockDatabase & { cluster?: { id: string; name: string } })[],
  databaseAPIs: [] as MockDatabaseAPI[],
  deletedDatabaseAPIs: [] as string[],
}))

// Mock Prisma
vi.mock('../../../utils/prisma.js', () => ({
  prisma: {
    database: {
      findMany: vi.fn().mockImplementation(async (options?: { where?: { clusterId?: string }; select?: object; skip?: number; take?: number }) => {
        let result = [...mockState.databases]
        if (options?.where?.clusterId) {
          result = result.filter((d) => d.clusterId === options.where!.clusterId)
        }
        if (options?.skip !== undefined && options?.take !== undefined) {
          result = result.slice(options.skip, options.skip + options.take)
        }
        return result
      }),
      findUnique: vi.fn().mockImplementation(async ({ where }: { where: { id: string } }) => {
        return mockState.databases.find((d) => d.id === where.id) || null
      }),
      create: vi.fn().mockImplementation(async ({ data }: { data: { type: string; host: string; port: number; username: string; password: string; clusterId: string; api?: { create: { address: string; api_key: string } } } }) => {
        const newDb: MockDatabase & { cluster?: { id: string; name: string } } = {
          id: '507f1f77bcf86cd799439099',
          type: data.type as 'postgresql' | 'mongodb' | 'influxdb',
          host: data.host,
          port: data.port,
          username: data.username,
          password: data.password,
          clusterId: data.clusterId,
          cluster: { id: data.clusterId, name: 'test-cluster' },
        }
        if (data.api?.create) {
          newDb.api = {
            id: '507f1f77bcf86cd799439098',
            address: data.api.create.address,
            api_key: data.api.create.api_key,
            databaseId: newDb.id,
          }
        }
        mockState.databases.push(newDb)
        return newDb
      }),
      update: vi.fn().mockImplementation(async ({ where, data }: { where: { id: string }; data: object }) => {
        const db = mockState.databases.find((d) => d.id === where.id)
        if (!db) throw new Error('Database not found')
        Object.assign(db, data)
        return db
      }),
      delete: vi.fn().mockImplementation(async ({ where }: { where: { id: string } }) => {
        const index = mockState.databases.findIndex((d) => d.id === where.id)
        if (index === -1) throw new Error('Database not found')
        const [deleted] = mockState.databases.splice(index, 1)
        return deleted
      }),
      count: vi.fn().mockImplementation(async (options?: { where?: { clusterId?: string } }) => {
        if (options?.where?.clusterId) {
          return mockState.databases.filter((d) => d.clusterId === options.where!.clusterId).length
        }
        return mockState.databases.length
      }),
    },
    databaseAPI: {
      deleteMany: vi.fn().mockImplementation(async ({ where }: { where: { databaseId: string } }) => {
        const toDelete = mockState.databaseAPIs.filter((api) => api.databaseId === where.databaseId)
        mockState.databaseAPIs = mockState.databaseAPIs.filter((api) => api.databaseId !== where.databaseId)
        mockState.deletedDatabaseAPIs.push(...toDelete.map((d) => d.id))
        return { count: toDelete.length }
      }),
    },
  },
}))

// Mock encryption
vi.mock('../../../utils/encryption.js', () => ({
  encryptPassword: vi.fn((password: string) => `encrypted:${password}`),
}))

// Mock getDatabasesAndRoles for listDatabasesFromServer
vi.mock('../../../database/postgresql.js', () => ({
  getDatabasesAndRoles: vi.fn().mockResolvedValue({
    test_db: {
      roles: [{ username: 'user1', adminUsername: 'admin1' }],
      size: 1024,
    },
  }),
}))

// Import after mocking
import { DatabaseService } from '../../../services/database.service.js'
import { prisma } from '../../../utils/prisma.js'
import { encryptPassword } from '../../../utils/encryption.js'
import { getDatabasesAndRoles } from '../../../database/postgresql.js'

describe('DatabaseService', () => {
  let service: DatabaseService

  beforeEach(() => {
    vi.clearAllMocks()

    // Reset mock state
    const cluster1Id = '507f1f77bcf86cd799439011'
    const cluster2Id = '507f1f77bcf86cd799439012'

    const db1 = createMockDatabase(cluster1Id, { id: '507f1f77bcf86cd799439021', type: 'postgresql' })
    const db2 = createMockDatabase(cluster1Id, { id: '507f1f77bcf86cd799439022', type: 'mongodb', port: 27017 })
    const db3 = createMockDatabase(cluster2Id, { id: '507f1f77bcf86cd799439023', type: 'postgresql' })

    const dbApi1 = createMockDatabaseAPI(db1.id, { id: '507f1f77bcf86cd799439031' })
    db1.api = dbApi1

    mockState.databases = [
      { ...db1, cluster: { id: cluster1Id, name: 'cluster-1' } },
      { ...db2, cluster: { id: cluster1Id, name: 'cluster-1' } },
      { ...db3, cluster: { id: cluster2Id, name: 'cluster-2' } },
    ]
    mockState.databaseAPIs = [dbApi1]
    mockState.deletedDatabaseAPIs = []

    service = new DatabaseService()
  })

  // ===========================================================================
  // getDatabases
  // ===========================================================================
  describe('getDatabases', () => {
    it('should return all databases', async () => {
      const result = await service.getDatabases()

      expect(result.data).toHaveLength(3)
      expect(result.total).toBe(3)
    })

    it('should filter by clusterId', async () => {
      const result = await service.getDatabases('507f1f77bcf86cd799439011')

      expect(prisma.database.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { clusterId: '507f1f77bcf86cd799439011' },
        })
      )
    })

    it('should support pagination', async () => {
      const result = await service.getDatabases(undefined, 1, 2)

      expect(prisma.database.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: 0,
          take: 2,
        })
      )
      expect(prisma.database.count).toHaveBeenCalled()
    })

    it('should include cluster and api relations in select', async () => {
      await service.getDatabases()

      expect(prisma.database.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          select: expect.objectContaining({
            cluster: expect.any(Object),
            api: expect.any(Object),
          }),
        })
      )
    })
  })

  // ===========================================================================
  // getDatabaseById
  // ===========================================================================
  describe('getDatabaseById', () => {
    it('should return database by ID', async () => {
      const result = await service.getDatabaseById('507f1f77bcf86cd799439021')

      expect(result).not.toBeNull()
      expect(result?.id).toBe('507f1f77bcf86cd799439021')
      expect(result?.type).toBe('postgresql')
    })

    it('should return null when database not found', async () => {
      const result = await service.getDatabaseById('non-existent-id')

      expect(result).toBeNull()
    })

    it('should include cluster and api relations', async () => {
      await service.getDatabaseById('507f1f77bcf86cd799439021')

      expect(prisma.database.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          select: expect.objectContaining({
            cluster: expect.any(Object),
            api: expect.any(Object),
          }),
        })
      )
    })
  })

  // ===========================================================================
  // createDatabase
  // ===========================================================================
  describe('createDatabase', () => {
    it('should create database and return result', async () => {
      const result = await service.createDatabase('507f1f77bcf86cd799439011', {
        type: 'postgresql',
        host: 'db.example.com',
        port: 5432,
        username: 'admin',
        password: 'secret123',
      })

      expect(result.id).toBeDefined()
      expect(result.type).toBe('postgresql')
      expect(result.host).toBe('db.example.com')
    })

    it('should encrypt password before storing', async () => {
      await service.createDatabase('507f1f77bcf86cd799439011', {
        type: 'postgresql',
        host: 'db.example.com',
        port: 5432,
        username: 'admin',
        password: 'secret123',
      })

      expect(encryptPassword).toHaveBeenCalledWith('secret123')
      expect(prisma.database.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            password: 'encrypted:secret123',
          }),
        })
      )
    })

    it('should create nested API if provided', async () => {
      const result = await service.createDatabase('507f1f77bcf86cd799439011', {
        type: 'postgresql',
        host: 'db.example.com',
        port: 5432,
        username: 'admin',
        password: 'secret123',
        api: {
          address: 'http://api.example.com',
          api_key: 'key-123',
        },
      })

      expect(prisma.database.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            api: {
              create: {
                address: 'http://api.example.com',
                api_key: 'key-123',
              },
            },
          }),
        })
      )
      expect(result.api).toBeDefined()
    })

    it('should work without API', async () => {
      await service.createDatabase('507f1f77bcf86cd799439011', {
        type: 'mongodb',
        host: 'mongo.example.com',
        port: 27017,
        username: 'admin',
        password: 'secret',
      })

      expect(prisma.database.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            api: undefined,
          }),
        })
      )
    })
  })

  // ===========================================================================
  // updateDatabase
  // ===========================================================================
  describe('updateDatabase', () => {
    it('should update database fields', async () => {
      await service.updateDatabase('507f1f77bcf86cd799439021', {
        host: 'new-host.example.com',
        port: 5433,
      })

      expect(prisma.database.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: '507f1f77bcf86cd799439021' },
          data: expect.objectContaining({
            host: 'new-host.example.com',
            port: 5433,
          }),
        })
      )
    })

    it('should encrypt password when provided', async () => {
      await service.updateDatabase('507f1f77bcf86cd799439021', {
        password: 'new-password',
      })

      expect(encryptPassword).toHaveBeenCalledWith('new-password')
      expect(prisma.database.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            password: 'encrypted:new-password',
          }),
        })
      )
    })

    it('should not encrypt password when not provided', async () => {
      await service.updateDatabase('507f1f77bcf86cd799439021', {
        host: 'new-host.example.com',
      })

      expect(encryptPassword).not.toHaveBeenCalled()
      expect(prisma.database.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            password: undefined,
          }),
        })
      )
    })

    it('should upsert API when provided', async () => {
      await service.updateDatabase('507f1f77bcf86cd799439021', {
        api: {
          address: 'http://new-api.example.com',
          api_key: 'new-key',
        },
      })

      expect(prisma.database.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            api: {
              upsert: {
                create: { address: 'http://new-api.example.com', api_key: 'new-key' },
                update: { address: 'http://new-api.example.com', api_key: 'new-key' },
              },
            },
          }),
        })
      )
    })
  })

  // ===========================================================================
  // deleteDatabase
  // ===========================================================================
  describe('deleteDatabase', () => {
    it('should delete database', async () => {
      const result = await service.deleteDatabase('507f1f77bcf86cd799439021')

      expect(prisma.database.delete).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: '507f1f77bcf86cd799439021' },
        })
      )
      expect(result.id).toBe('507f1f77bcf86cd799439021')
    })

    it('should cascade delete associated DatabaseAPI', async () => {
      // db1 has an API
      await service.deleteDatabase('507f1f77bcf86cd799439021')

      expect(prisma.databaseAPI.deleteMany).toHaveBeenCalledWith({
        where: { databaseId: '507f1f77bcf86cd799439021' },
      })
      expect(mockState.deletedDatabaseAPIs).toContain('507f1f77bcf86cd799439031')
    })

    it('should handle database with no API', async () => {
      // db2 has no API
      await service.deleteDatabase('507f1f77bcf86cd799439022')

      expect(prisma.databaseAPI.deleteMany).toHaveBeenCalledWith({
        where: { databaseId: '507f1f77bcf86cd799439022' },
      })
      // Should not throw, just delete 0 records
    })
  })

  // ===========================================================================
  // listDatabasesFromServer
  // ===========================================================================
  describe('listDatabasesFromServer', () => {
    it('should return databases from actual server', async () => {
      const result = await service.listDatabasesFromServer('507f1f77bcf86cd799439021')

      expect(getDatabasesAndRoles).toHaveBeenCalled()
      expect(result).toEqual({
        test_db: {
          roles: [{ username: 'user1', adminUsername: 'admin1' }],
          size: 1024,
        },
      })
    })

    it('should throw error when database not found', async () => {
      await expect(service.listDatabasesFromServer('non-existent-id')).rejects.toThrow(
        'Database configuration not found'
      )
    })

    it('should pass database config with API to getDatabasesAndRoles', async () => {
      await service.listDatabasesFromServer('507f1f77bcf86cd799439021')

      expect(getDatabasesAndRoles).toHaveBeenCalledWith(
        expect.objectContaining({
          id: '507f1f77bcf86cd799439021',
          type: 'postgresql',
          api: expect.objectContaining({
            address: 'http://api.example.com',
          }),
        })
      )
    })
  })
})
