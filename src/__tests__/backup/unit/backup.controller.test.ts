import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import { createMockBackup, createMockBackupItem } from '../../cluster/fixtures/cluster.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  backups: [] as Array<{
    id: string
    database_type: string
    date: Date
    size: string
    clusterId: string
    BackupItem: Array<object>
    backupItemCount: number
  }>,
}))

// Mock backup service
vi.mock('../../../services/backup.service.js', () => ({
  backupService: {
    getBackups: vi.fn().mockImplementation(async (clusterId?: string) => {
      if (clusterId) {
        return mockState.backups.filter((b) => b.clusterId === clusterId)
      }
      return mockState.backups
    }),
    getBackupById: vi.fn().mockImplementation(async (id: string) => {
      return mockState.backups.find((b) => b.id === id) || null
    }),
    createBackup: vi.fn().mockImplementation(async (clusterId: string, data: object) => ({
      id: '507f1f77bcf86cd799439099',
      ...data,
      clusterId,
      BackupItem: [],
      backupItemCount: 0,
    })),
    deleteBackup: vi.fn().mockImplementation(async (id: string) => {
      const backup = mockState.backups.find((b) => b.id === id)
      if (!backup) throw new Error('Not found')
      return backup
    }),
  },
}))

// Import after mocking
import { BackupController } from '../../../controllers/backup.controller.js'
import { backupService } from '../../../services/backup.service.js'

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

describe('BackupController', () => {
  let controller: BackupController

  beforeEach(() => {
    vi.clearAllMocks()

    const backup1 = createMockBackup('507f1f77bcf86cd799439011', { id: '507f1f77bcf86cd799439041' })
    const backup2 = createMockBackup('507f1f77bcf86cd799439011', { id: '507f1f77bcf86cd799439042' })

    const item1 = createMockBackupItem(backup1.id, { id: '507f1f77bcf86cd799439051' })

    mockState.backups = [
      {
        id: backup1.id,
        database_type: backup1.database_type,
        date: backup1.date,
        size: backup1.size,
        clusterId: backup1.clusterId,
        BackupItem: [item1],
        backupItemCount: 1,
      },
      {
        id: backup2.id,
        database_type: backup2.database_type,
        date: backup2.date,
        size: backup2.size,
        clusterId: backup2.clusterId,
        BackupItem: [],
        backupItemCount: 0,
      },
    ]

    controller = new BackupController()
  })

  // ===========================================================================
  // getBackups
  // ===========================================================================
  describe('getBackups', () => {
    it('should return all backups', async () => {
      const request = createMockRequest({ query: {} })
      const reply = createMockReply()

      await controller.getBackups(
        request as FastifyRequest<{ Querystring: { clusterId?: string } }>,
        reply
      )

      expect(backupService.getBackups).toHaveBeenCalledWith(undefined)
      expect(reply._body).toHaveLength(2)
    })

    it('should pass clusterId filter to service', async () => {
      const request = createMockRequest({ query: { clusterId: '507f1f77bcf86cd799439011' } })
      const reply = createMockReply()

      await controller.getBackups(
        request as FastifyRequest<{ Querystring: { clusterId?: string } }>,
        reply
      )

      expect(backupService.getBackups).toHaveBeenCalledWith('507f1f77bcf86cd799439011')
    })
  })

  // ===========================================================================
  // getBackupById
  // ===========================================================================
  describe('getBackupById', () => {
    it('should return backup when found', async () => {
      const request = createMockRequest({ params: { id: '507f1f77bcf86cd799439041' } })
      const reply = createMockReply()

      await controller.getBackupById(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._body).toBeDefined()
      expect((reply._body as { id: string }).id).toBe('507f1f77bcf86cd799439041')
    })

    it('should return 404 when backup not found', async () => {
      const request = createMockRequest({ params: { id: 'non-existent' } })
      const reply = createMockReply()

      await controller.getBackupById(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(404)
      expect((reply._body as { message: string }).message).toBe('Backup not found')
    })
  })

  // ===========================================================================
  // createBackup
  // ===========================================================================
  describe('createBackup', () => {
    it('should return 201 status', async () => {
      const request = createMockRequest({
        params: { clusterId: '507f1f77bcf86cd799439011' },
        body: {
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
        },
      })
      const reply = createMockReply()

      await controller.createBackup(
        request as FastifyRequest<{ Params: { clusterId: string }; Body: object }>,
        reply
      )

      expect(reply._statusCode).toBe(201)
      expect(reply._body).toBeDefined()
    })

    it('should pass clusterId from params', async () => {
      const backupData = {
        database_type: 'postgresql',
        date: new Date('2024-02-01'),
        size: '500MB',
        backupItems: [],
      }
      const request = createMockRequest({
        params: { clusterId: '507f1f77bcf86cd799439011' },
        body: backupData,
      })
      const reply = createMockReply()

      await controller.createBackup(
        request as FastifyRequest<{ Params: { clusterId: string }; Body: typeof backupData }>,
        reply
      )

      expect(backupService.createBackup).toHaveBeenCalledWith('507f1f77bcf86cd799439011', backupData)
    })
  })

  // ===========================================================================
  // deleteBackup
  // ===========================================================================
  describe('deleteBackup', () => {
    it('should return deleted backup', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439041' },
      })
      const reply = createMockReply()

      await controller.deleteBackup(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(backupService.deleteBackup).toHaveBeenCalledWith('507f1f77bcf86cd799439041')
      expect(reply._body).toBeDefined()
    })
  })
})
