import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  createMockBackup,
  createMockBackupItem,
  MockBackupItem,
} from '../../cluster/fixtures/cluster.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  backupItems: [] as (MockBackupItem & { backup?: { id: string; database_type: string; date: Date } })[],
}))

// Mock Prisma
vi.mock('../../../utils/prisma.js', () => ({
  prisma: {
    backupItem: {
      findMany: vi.fn().mockImplementation(async (options?: { where?: { backupId?: string }; include?: object }) => {
        if (options?.where?.backupId) {
          return mockState.backupItems.filter((item) => item.backupId === options.where!.backupId)
        }
        return mockState.backupItems
      }),
      findUnique: vi.fn().mockImplementation(async ({ where }: { where: { id: string } }) => {
        return mockState.backupItems.find((item) => item.id === where.id) || null
      }),
      create: vi.fn().mockImplementation(async ({ data }: { data: { database_type: string; name: string; admin_username: string; username: string; filename: string; date: Date; backupId: string } }) => {
        const newItem: MockBackupItem & { backup?: { id: string; database_type: string; date: Date } } = {
          id: '507f1f77bcf86cd799439099',
          database_type: data.database_type,
          name: data.name,
          admin_username: data.admin_username,
          username: data.username,
          filename: data.filename,
          date: data.date,
          backupId: data.backupId,
          backup: { id: data.backupId, database_type: 'postgresql', date: new Date('2024-01-15') },
        }
        mockState.backupItems.push(newItem)
        return newItem
      }),
      update: vi.fn().mockImplementation(async ({ where, data }: { where: { id: string }; data: object }) => {
        const item = mockState.backupItems.find((i) => i.id === where.id)
        if (!item) throw new Error('BackupItem not found')
        Object.assign(item, data)
        return item
      }),
      delete: vi.fn().mockImplementation(async ({ where }: { where: { id: string } }) => {
        const index = mockState.backupItems.findIndex((i) => i.id === where.id)
        if (index === -1) throw new Error('BackupItem not found')
        const [deleted] = mockState.backupItems.splice(index, 1)
        return deleted
      }),
    },
  },
}))

// Import after mocking
import { BackupItemService } from '../../../services/backup-item.service.js'
import { prisma } from '../../../utils/prisma.js'

describe('BackupItemService', () => {
  let service: BackupItemService

  beforeEach(() => {
    vi.clearAllMocks()

    const backup1 = createMockBackup('507f1f77bcf86cd799439011', { id: '507f1f77bcf86cd799439041' })
    const backup2 = createMockBackup('507f1f77bcf86cd799439011', { id: '507f1f77bcf86cd799439042' })

    const item1 = createMockBackupItem(backup1.id, { id: '507f1f77bcf86cd799439051', name: 'db1' })
    const item2 = createMockBackupItem(backup1.id, { id: '507f1f77bcf86cd799439052', name: 'db2' })
    const item3 = createMockBackupItem(backup2.id, { id: '507f1f77bcf86cd799439053', name: 'db3' })

    mockState.backupItems = [
      { ...item1, backup: { id: backup1.id, database_type: backup1.database_type, date: backup1.date } },
      { ...item2, backup: { id: backup1.id, database_type: backup1.database_type, date: backup1.date } },
      { ...item3, backup: { id: backup2.id, database_type: backup2.database_type, date: backup2.date } },
    ]

    service = new BackupItemService()
  })

  // ===========================================================================
  // getBackupItems
  // ===========================================================================
  describe('getBackupItems', () => {
    it('should return all backup items', async () => {
      const result = await service.getBackupItems()

      expect(result).toHaveLength(3)
    })

    it('should filter by backupId', async () => {
      const result = await service.getBackupItems('507f1f77bcf86cd799439041')

      expect(prisma.backupItem.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { backupId: '507f1f77bcf86cd799439041' },
        })
      )
    })

    it('should include backup relation', async () => {
      await service.getBackupItems()

      expect(prisma.backupItem.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          include: expect.objectContaining({
            backup: expect.any(Object),
          }),
        })
      )
    })
  })

  // ===========================================================================
  // getBackupItemById
  // ===========================================================================
  describe('getBackupItemById', () => {
    it('should return backup item by ID', async () => {
      const result = await service.getBackupItemById('507f1f77bcf86cd799439051')

      expect(result).not.toBeNull()
      expect(result?.id).toBe('507f1f77bcf86cd799439051')
      expect(result?.name).toBe('db1')
    })

    it('should return null when not found', async () => {
      const result = await service.getBackupItemById('non-existent-id')

      expect(result).toBeNull()
    })

    it('should include backup relation', async () => {
      await service.getBackupItemById('507f1f77bcf86cd799439051')

      expect(prisma.backupItem.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          include: expect.objectContaining({
            backup: expect.any(Object),
          }),
        })
      )
    })
  })

  // ===========================================================================
  // createBackupItem
  // ===========================================================================
  describe('createBackupItem', () => {
    it('should create backup item', async () => {
      const result = await service.createBackupItem('507f1f77bcf86cd799439041', {
        database_type: 'postgresql',
        name: 'new_db',
        admin_username: 'admin',
        username: 'user',
        filename: 'backup.sql',
        date: new Date('2024-02-01'),
      })

      expect(result.id).toBeDefined()
      expect(result.name).toBe('new_db')
    })

    it('should link to backup', async () => {
      await service.createBackupItem('507f1f77bcf86cd799439041', {
        database_type: 'postgresql',
        name: 'new_db',
        admin_username: 'admin',
        username: 'user',
        filename: 'backup.sql',
        date: new Date('2024-02-01'),
      })

      expect(prisma.backupItem.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            backupId: '507f1f77bcf86cd799439041',
          }),
        })
      )
    })

    it('should include backup relation in response', async () => {
      await service.createBackupItem('507f1f77bcf86cd799439041', {
        database_type: 'postgresql',
        name: 'new_db',
        admin_username: 'admin',
        username: 'user',
        filename: 'backup.sql',
        date: new Date('2024-02-01'),
      })

      expect(prisma.backupItem.create).toHaveBeenCalledWith(
        expect.objectContaining({
          include: expect.objectContaining({
            backup: expect.any(Object),
          }),
        })
      )
    })
  })

  // ===========================================================================
  // updateBackupItem
  // ===========================================================================
  describe('updateBackupItem', () => {
    it('should update backup item fields', async () => {
      const result = await service.updateBackupItem('507f1f77bcf86cd799439051', {
        name: 'updated_db',
        filename: 'updated_backup.sql',
      })

      expect(result.name).toBe('updated_db')
      expect(result.filename).toBe('updated_backup.sql')
    })

    it('should call prisma with correct params', async () => {
      await service.updateBackupItem('507f1f77bcf86cd799439051', {
        name: 'updated_db',
        admin_username: 'new_admin',
      })

      expect(prisma.backupItem.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: '507f1f77bcf86cd799439051' },
          data: expect.objectContaining({
            name: 'updated_db',
            admin_username: 'new_admin',
          }),
        })
      )
    })

    it('should support partial updates', async () => {
      await service.updateBackupItem('507f1f77bcf86cd799439051', {
        name: 'only_name_updated',
      })

      expect(prisma.backupItem.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            name: 'only_name_updated',
          }),
        })
      )
    })
  })

  // ===========================================================================
  // deleteBackupItem
  // ===========================================================================
  describe('deleteBackupItem', () => {
    it('should delete backup item', async () => {
      const result = await service.deleteBackupItem('507f1f77bcf86cd799439051')

      expect(result.id).toBe('507f1f77bcf86cd799439051')
      expect(mockState.backupItems).toHaveLength(2)
    })

    it('should call prisma with correct params', async () => {
      await service.deleteBackupItem('507f1f77bcf86cd799439051')

      expect(prisma.backupItem.delete).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: '507f1f77bcf86cd799439051' },
        })
      )
    })
  })
})
