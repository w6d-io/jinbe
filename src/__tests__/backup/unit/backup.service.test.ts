import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  createMockBackup,
  createMockBackupItem,
  MockBackup,
  MockBackupItem,
} from '../../cluster/fixtures/cluster.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  backups: [] as (MockBackup & { cluster?: { id: string; name: string } })[],
  backupItems: [] as MockBackupItem[],
  deletedBackupItems: [] as string[],
}))

// Mock Prisma
vi.mock('../../../utils/prisma.js', () => ({
  prisma: {
    backup: {
      findMany: vi.fn().mockImplementation(async (options?: { where?: { clusterId?: string }; include?: object }) => {
        let result = [...mockState.backups]
        if (options?.where?.clusterId) {
          result = result.filter((b) => b.clusterId === options.where!.clusterId)
        }
        // Add BackupItem to each backup
        return result.map((backup) => ({
          ...backup,
          BackupItem: mockState.backupItems.filter((item) => item.backupId === backup.id),
        }))
      }),
      findUnique: vi.fn().mockImplementation(async ({ where }: { where: { id: string } }) => {
        const backup = mockState.backups.find((b) => b.id === where.id)
        if (!backup) return null
        return {
          ...backup,
          BackupItem: mockState.backupItems.filter((item) => item.backupId === backup.id),
        }
      }),
      create: vi.fn().mockImplementation(async ({ data }: { data: { database_type: string; date: Date; size: string; clusterId: string; BackupItem?: { create: Array<object> } } }) => {
        const newBackup: MockBackup & { cluster?: { id: string; name: string } } = {
          id: '507f1f77bcf86cd799439099',
          database_type: data.database_type,
          date: data.date,
          size: data.size,
          clusterId: data.clusterId,
          cluster: { id: data.clusterId, name: 'test-cluster' },
        }
        mockState.backups.push(newBackup)

        // Create BackupItems
        const createdItems: MockBackupItem[] = []
        if (data.BackupItem?.create) {
          data.BackupItem.create.forEach((itemData: any, index: number) => {
            const item: MockBackupItem = {
              id: `507f1f77bcf86cd799439${100 + index}`,
              database_type: itemData.database_type,
              name: itemData.name,
              admin_username: itemData.admin_username,
              username: itemData.username,
              filename: itemData.filename,
              date: itemData.date,
              backupId: newBackup.id,
            }
            mockState.backupItems.push(item)
            createdItems.push(item)
          })
        }

        return { ...newBackup, BackupItem: createdItems }
      }),
      delete: vi.fn().mockImplementation(async ({ where }: { where: { id: string } }) => {
        const index = mockState.backups.findIndex((b) => b.id === where.id)
        if (index === -1) throw new Error('Backup not found')
        const [deleted] = mockState.backups.splice(index, 1)
        return deleted
      }),
    },
    backupItem: {
      deleteMany: vi.fn().mockImplementation(async ({ where }: { where: { backupId: string } }) => {
        const toDelete = mockState.backupItems.filter((item) => item.backupId === where.backupId)
        mockState.backupItems = mockState.backupItems.filter((item) => item.backupId !== where.backupId)
        mockState.deletedBackupItems.push(...toDelete.map((d) => d.id))
        return { count: toDelete.length }
      }),
    },
  },
}))

// Import after mocking
import { BackupService } from '../../../services/backup.service.js'
import { prisma } from '../../../utils/prisma.js'

describe('BackupService', () => {
  let service: BackupService

  beforeEach(() => {
    vi.clearAllMocks()

    const cluster1Id = '507f1f77bcf86cd799439011'
    const cluster2Id = '507f1f77bcf86cd799439012'

    const backup1 = createMockBackup(cluster1Id, { id: '507f1f77bcf86cd799439041', database_type: 'postgresql' })
    const backup2 = createMockBackup(cluster1Id, { id: '507f1f77bcf86cd799439042', database_type: 'mongodb' })
    const backup3 = createMockBackup(cluster2Id, { id: '507f1f77bcf86cd799439043', database_type: 'postgresql' })

    const item1 = createMockBackupItem(backup1.id, { id: '507f1f77bcf86cd799439051', name: 'db1' })
    const item2 = createMockBackupItem(backup1.id, { id: '507f1f77bcf86cd799439052', name: 'db2' })
    const item3 = createMockBackupItem(backup2.id, { id: '507f1f77bcf86cd799439053', name: 'db3' })

    mockState.backups = [
      { ...backup1, cluster: { id: cluster1Id, name: 'cluster-1' } },
      { ...backup2, cluster: { id: cluster1Id, name: 'cluster-1' } },
      { ...backup3, cluster: { id: cluster2Id, name: 'cluster-2' } },
    ]
    mockState.backupItems = [item1, item2, item3]
    mockState.deletedBackupItems = []

    service = new BackupService()
  })

  // ===========================================================================
  // getBackups
  // ===========================================================================
  describe('getBackups', () => {
    it('should return all backups', async () => {
      const result = await service.getBackups()

      expect(result).toHaveLength(3)
    })

    it('should filter by clusterId', async () => {
      const result = await service.getBackups('507f1f77bcf86cd799439011')

      expect(prisma.backup.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { clusterId: '507f1f77bcf86cd799439011' },
        })
      )
    })

    it('should include BackupItem relation', async () => {
      await service.getBackups()

      expect(prisma.backup.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          include: expect.objectContaining({
            BackupItem: true,
          }),
        })
      )
    })

    it('should include cluster relation', async () => {
      await service.getBackups()

      expect(prisma.backup.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          include: expect.objectContaining({
            cluster: expect.any(Object),
          }),
        })
      )
    })

    it('should add computed backupItemCount', async () => {
      const result = await service.getBackups()

      expect(result[0].backupItemCount).toBe(2) // backup1 has 2 items
      expect(result[1].backupItemCount).toBe(1) // backup2 has 1 item
      expect(result[2].backupItemCount).toBe(0) // backup3 has 0 items
    })
  })

  // ===========================================================================
  // getBackupById
  // ===========================================================================
  describe('getBackupById', () => {
    it('should return backup by ID', async () => {
      const result = await service.getBackupById('507f1f77bcf86cd799439041')

      expect(result).not.toBeNull()
      expect(result?.id).toBe('507f1f77bcf86cd799439041')
      expect(result?.database_type).toBe('postgresql')
    })

    it('should return null when backup not found', async () => {
      const result = await service.getBackupById('non-existent-id')

      expect(result).toBeNull()
    })

    it('should include BackupItem and cluster relations', async () => {
      await service.getBackupById('507f1f77bcf86cd799439041')

      expect(prisma.backup.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          include: expect.objectContaining({
            BackupItem: true,
            cluster: expect.any(Object),
          }),
        })
      )
    })

    it('should add computed backupItemCount', async () => {
      const result = await service.getBackupById('507f1f77bcf86cd799439041')

      expect(result?.backupItemCount).toBe(2)
    })
  })

  // ===========================================================================
  // createBackup
  // ===========================================================================
  describe('createBackup', () => {
    it('should create backup and return result', async () => {
      const result = await service.createBackup('507f1f77bcf86cd799439011', {
        database_type: 'postgresql',
        date: new Date('2024-02-01'),
        size: '500MB',
        backupItems: [
          {
            database_type: 'postgresql',
            name: 'test_db',
            admin_username: 'admin',
            username: 'user',
            filename: 'backup.sql',
            date: new Date('2024-02-01'),
          },
        ],
      })

      expect(result.id).toBeDefined()
      expect(result.database_type).toBe('postgresql')
      expect(result.size).toBe('500MB')
    })

    it('should create nested BackupItems', async () => {
      const backupData = {
        database_type: 'postgresql',
        date: new Date('2024-02-01'),
        size: '500MB',
        backupItems: [
          {
            database_type: 'postgresql',
            name: 'db1',
            admin_username: 'admin1',
            username: 'user1',
            filename: 'db1.sql',
            date: new Date('2024-02-01'),
          },
          {
            database_type: 'postgresql',
            name: 'db2',
            admin_username: 'admin2',
            username: 'user2',
            filename: 'db2.sql',
            date: new Date('2024-02-01'),
          },
        ],
      }

      const result = await service.createBackup('507f1f77bcf86cd799439011', backupData)

      expect(prisma.backup.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            BackupItem: expect.objectContaining({
              create: expect.any(Array),
            }),
          }),
        })
      )
      expect(result.backupItemCount).toBe(2)
    })

    it('should pass backup date to all BackupItems', async () => {
      const backupDate = new Date('2024-02-01')
      await service.createBackup('507f1f77bcf86cd799439011', {
        database_type: 'postgresql',
        date: backupDate,
        size: '500MB',
        backupItems: [
          {
            database_type: 'postgresql',
            name: 'test_db',
            admin_username: 'admin',
            username: 'user',
            filename: 'backup.sql',
            date: new Date('2024-01-15'), // Different date
          },
        ],
      })

      // The service should override item dates with backup date
      expect(prisma.backup.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            BackupItem: {
              create: expect.arrayContaining([
                expect.objectContaining({
                  date: backupDate,
                }),
              ]),
            },
          }),
        })
      )
    })
  })

  // ===========================================================================
  // deleteBackup
  // ===========================================================================
  describe('deleteBackup', () => {
    it('should delete backup', async () => {
      const result = await service.deleteBackup('507f1f77bcf86cd799439041')

      expect(prisma.backup.delete).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: '507f1f77bcf86cd799439041' },
        })
      )
      expect(result.id).toBe('507f1f77bcf86cd799439041')
    })

    it('should cascade delete BackupItems first', async () => {
      await service.deleteBackup('507f1f77bcf86cd799439041')

      // Should delete items before backup
      expect(prisma.backupItem.deleteMany).toHaveBeenCalledWith({
        where: { backupId: '507f1f77bcf86cd799439041' },
      })
      expect(mockState.deletedBackupItems).toContain('507f1f77bcf86cd799439051')
      expect(mockState.deletedBackupItems).toContain('507f1f77bcf86cd799439052')
    })

    it('should handle backup with no items', async () => {
      // backup3 has no items
      await service.deleteBackup('507f1f77bcf86cd799439043')

      expect(prisma.backupItem.deleteMany).toHaveBeenCalledWith({
        where: { backupId: '507f1f77bcf86cd799439043' },
      })
      // Should not throw, just delete 0 records
    })
  })
})
