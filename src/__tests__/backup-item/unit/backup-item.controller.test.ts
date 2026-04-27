import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import { createMockBackupItem } from '../../cluster/fixtures/cluster.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  backupItems: [] as Array<{
    id: string
    database_type: string
    name: string
    admin_username: string
    username: string
    filename: string
    date: Date
    backupId: string
    backup?: { id: string; database_type: string; date: Date }
  }>,
}))

// Mock backup-item service
vi.mock('../../../services/backup-item.service.js', () => ({
  backupItemService: {
    getBackupItems: vi.fn().mockImplementation(async (backupId?: string) => {
      if (backupId) {
        return mockState.backupItems.filter((item) => item.backupId === backupId)
      }
      return mockState.backupItems
    }),
    getBackupItemById: vi.fn().mockImplementation(async (id: string) => {
      return mockState.backupItems.find((item) => item.id === id) || null
    }),
    createBackupItem: vi.fn().mockImplementation(async (backupId: string, data: object) => ({
      id: '507f1f77bcf86cd799439099',
      ...data,
      backupId,
      backup: { id: backupId, database_type: 'postgresql', date: new Date('2024-01-15') },
    })),
    updateBackupItem: vi.fn().mockImplementation(async (id: string, data: object) => {
      const item = mockState.backupItems.find((i) => i.id === id)
      if (!item) throw new Error('Not found')
      return { ...item, ...data }
    }),
    deleteBackupItem: vi.fn().mockImplementation(async (id: string) => {
      const item = mockState.backupItems.find((i) => i.id === id)
      if (!item) throw new Error('Not found')
      return item
    }),
  },
}))

// Import after mocking
import { BackupItemController } from '../../../controllers/backup-item.controller.js'
import { backupItemService } from '../../../services/backup-item.service.js'

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

describe('BackupItemController', () => {
  let controller: BackupItemController

  beforeEach(() => {
    vi.clearAllMocks()

    const item1 = createMockBackupItem('507f1f77bcf86cd799439041', { id: '507f1f77bcf86cd799439051', name: 'db1' })
    const item2 = createMockBackupItem('507f1f77bcf86cd799439041', { id: '507f1f77bcf86cd799439052', name: 'db2' })
    const item3 = createMockBackupItem('507f1f77bcf86cd799439042', { id: '507f1f77bcf86cd799439053', name: 'db3' })

    mockState.backupItems = [
      { ...item1, backup: { id: '507f1f77bcf86cd799439041', database_type: 'postgresql', date: new Date('2024-01-15') } },
      { ...item2, backup: { id: '507f1f77bcf86cd799439041', database_type: 'postgresql', date: new Date('2024-01-15') } },
      { ...item3, backup: { id: '507f1f77bcf86cd799439042', database_type: 'mongodb', date: new Date('2024-01-15') } },
    ]

    controller = new BackupItemController()
  })

  // ===========================================================================
  // getBackupItems
  // ===========================================================================
  describe('getBackupItems', () => {
    it('should return all backup items', async () => {
      const request = createMockRequest({ query: {} })
      const reply = createMockReply()

      await controller.getBackupItems(
        request as FastifyRequest<{ Querystring: { backupId?: string } }>,
        reply
      )

      expect(backupItemService.getBackupItems).toHaveBeenCalledWith(undefined)
      expect(reply._body).toHaveLength(3)
    })

    it('should pass backupId filter to service', async () => {
      const request = createMockRequest({ query: { backupId: '507f1f77bcf86cd799439041' } })
      const reply = createMockReply()

      await controller.getBackupItems(
        request as FastifyRequest<{ Querystring: { backupId?: string } }>,
        reply
      )

      expect(backupItemService.getBackupItems).toHaveBeenCalledWith('507f1f77bcf86cd799439041')
    })
  })

  // ===========================================================================
  // getBackupItemById
  // ===========================================================================
  describe('getBackupItemById', () => {
    it('should return backup item when found', async () => {
      const request = createMockRequest({ params: { id: '507f1f77bcf86cd799439051' } })
      const reply = createMockReply()

      await controller.getBackupItemById(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._body).toBeDefined()
      expect((reply._body as { id: string }).id).toBe('507f1f77bcf86cd799439051')
    })

    it('should return 404 when not found', async () => {
      const request = createMockRequest({ params: { id: 'non-existent' } })
      const reply = createMockReply()

      await controller.getBackupItemById(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(404)
      expect((reply._body as { message: string }).message).toBe('Backup item not found')
    })
  })

  // ===========================================================================
  // createBackupItem
  // ===========================================================================
  describe('createBackupItem', () => {
    it('should return 201 status', async () => {
      const request = createMockRequest({
        params: { backupId: '507f1f77bcf86cd799439041' },
        body: {
          database_type: 'postgresql',
          name: 'new_db',
          admin_username: 'admin',
          username: 'user',
          filename: 'backup.sql',
          date: new Date('2024-02-01'),
        },
      })
      const reply = createMockReply()

      await controller.createBackupItem(
        request as FastifyRequest<{ Params: { backupId: string }; Body: object }>,
        reply
      )

      expect(reply._statusCode).toBe(201)
      expect(reply._body).toBeDefined()
    })

    it('should pass backupId from params', async () => {
      const itemData = {
        database_type: 'postgresql',
        name: 'new_db',
        admin_username: 'admin',
        username: 'user',
        filename: 'backup.sql',
        date: new Date('2024-02-01'),
      }
      const request = createMockRequest({
        params: { backupId: '507f1f77bcf86cd799439041' },
        body: itemData,
      })
      const reply = createMockReply()

      await controller.createBackupItem(
        request as FastifyRequest<{ Params: { backupId: string }; Body: typeof itemData }>,
        reply
      )

      expect(backupItemService.createBackupItem).toHaveBeenCalledWith('507f1f77bcf86cd799439041', itemData)
    })
  })

  // ===========================================================================
  // updateBackupItem
  // ===========================================================================
  describe('updateBackupItem', () => {
    it('should return updated item', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439051' },
        body: { name: 'updated_db' },
      })
      const reply = createMockReply()

      await controller.updateBackupItem(
        request as FastifyRequest<{ Params: { id: string }; Body: { name: string } }>,
        reply
      )

      expect(backupItemService.updateBackupItem).toHaveBeenCalledWith(
        '507f1f77bcf86cd799439051',
        { name: 'updated_db' }
      )
      expect(reply._body).toBeDefined()
    })
  })

  // ===========================================================================
  // deleteBackupItem
  // ===========================================================================
  describe('deleteBackupItem', () => {
    it('should return deleted item', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439051' },
      })
      const reply = createMockReply()

      await controller.deleteBackupItem(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(backupItemService.deleteBackupItem).toHaveBeenCalledWith('507f1f77bcf86cd799439051')
      expect(reply._body).toBeDefined()
    })
  })
})
