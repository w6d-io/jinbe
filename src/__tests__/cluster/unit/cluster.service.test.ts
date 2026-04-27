import { describe, it, expect, beforeEach, vi } from 'vitest'

// Mock state using vi.hoisted - must be self-contained, no external imports
const mockState = vi.hoisted(() => ({
  clusters: [] as Array<{
    id: string
    name: string
    config: string
    createdAt: Date
    updatedAt: Date
    _count?: { databases: number; backups: number }
  }>,
  databases: [] as Array<{
    id: string
    type: string
    host: string
    port: number
    username: string
    clusterId: string
  }>,
  databaseAPIs: [] as Array<{ id: string; databaseId: string }>,
  backups: [] as Array<{ id: string; clusterId: string }>,
  backupItems: [] as Array<{ id: string; backupId: string }>,
  verificationResult: {
    success: true,
    cluster: { name: 'test-cluster', server: 'https://k8s.example.com:6443', version: 'v1.28.0' },
    user: { name: 'test-user', authMethod: 'token' as const },
    identity: { username: 'test-sa', groups: ['system:authenticated'] },
    permissions: { canListNamespaces: true, canListPods: true, canCreateJobs: true, canListSecrets: false },
  },
  deletedBackupItems: [] as string[],
  deletedDatabaseAPIs: [] as string[],
  deletedBackups: [] as string[],
  deletedDatabases: [] as string[],
}))

// Import fixtures after vi.hoisted (for use in tests, not mocks)
import {
  createMockCluster,
  createMockDatabase,
  createClusterWithCascadeData,
  sampleKubeconfig,
  sampleVerificationResult,
} from '../fixtures/cluster.fixture.js'

// Mock Prisma
vi.mock('../../../utils/prisma.js', () => ({
  prisma: {
    cluster: {
      findMany: vi.fn().mockImplementation(async () => mockState.clusters),
      findUnique: vi.fn().mockImplementation(async ({ where }) => {
        return mockState.clusters.find((c) => c.id === where.id) || null
      }),
      create: vi.fn().mockImplementation(async ({ data }) => {
        const newCluster = {
          id: '507f1f77bcf86cd799439099',
          name: data.name,
          config: data.config,
          createdAt: new Date(),
          updatedAt: new Date(),
          _count: { databases: 0, backups: 0 },
        }
        mockState.clusters.push(newCluster)
        return newCluster
      }),
      update: vi.fn().mockImplementation(async ({ where, data }) => {
        const cluster = mockState.clusters.find((c) => c.id === where.id)
        if (!cluster) throw new Error('Cluster not found')
        Object.assign(cluster, data)
        return cluster
      }),
      delete: vi.fn().mockImplementation(async ({ where }) => {
        const index = mockState.clusters.findIndex((c) => c.id === where.id)
        if (index === -1) throw new Error('Cluster not found')
        const [deleted] = mockState.clusters.splice(index, 1)
        return deleted
      }),
      count: vi.fn().mockImplementation(async () => mockState.clusters.length),
    },
    database: {
      findMany: vi.fn().mockImplementation(async ({ where }) => {
        return mockState.databases.filter((d) => d.clusterId === where.clusterId)
      }),
      deleteMany: vi.fn().mockImplementation(async ({ where }) => {
        // Check if there are DatabaseAPIs that would block deletion
        const dbIds = mockState.databases
          .filter((d) => d.clusterId === where.clusterId)
          .map((d) => d.id)

        const hasBlockingAPIs = mockState.databaseAPIs.some((api) =>
          dbIds.includes(api.databaseId)
        )

        if (hasBlockingAPIs && mockState.deletedDatabaseAPIs.length === 0) {
          // Simulate foreign key constraint error
          throw new Error(
            'Foreign key constraint failed: DatabaseAPI references this Database'
          )
        }

        const deleted = mockState.databases.filter((d) => d.clusterId === where.clusterId)
        mockState.databases = mockState.databases.filter((d) => d.clusterId !== where.clusterId)
        mockState.deletedDatabases.push(...deleted.map((d) => d.id))
        return { count: deleted.length }
      }),
    },
    databaseAPI: {
      deleteMany: vi.fn().mockImplementation(async ({ where }) => {
        let deleted: Array<{ id: string; databaseId: string }> = []
        if (where.databaseId?.in) {
          deleted = mockState.databaseAPIs.filter((api) =>
            where.databaseId.in.includes(api.databaseId)
          )
          mockState.databaseAPIs = mockState.databaseAPIs.filter(
            (api) => !where.databaseId.in.includes(api.databaseId)
          )
        }
        mockState.deletedDatabaseAPIs.push(...deleted.map((d) => d.id))
        return { count: deleted.length }
      }),
    },
    backup: {
      findMany: vi.fn().mockImplementation(async ({ where }) => {
        return mockState.backups.filter((b) => b.clusterId === where.clusterId)
      }),
      deleteMany: vi.fn().mockImplementation(async ({ where }) => {
        // Check if there are BackupItems that would block deletion
        const backupIds = mockState.backups
          .filter((b) => b.clusterId === where.clusterId)
          .map((b) => b.id)

        const hasBlockingItems = mockState.backupItems.some((item) =>
          backupIds.includes(item.backupId)
        )

        if (hasBlockingItems && mockState.deletedBackupItems.length === 0) {
          // Simulate foreign key constraint error
          throw new Error(
            'Foreign key constraint failed: BackupItem references this Backup'
          )
        }

        const deleted = mockState.backups.filter((b) => b.clusterId === where.clusterId)
        mockState.backups = mockState.backups.filter((b) => b.clusterId !== where.clusterId)
        mockState.deletedBackups.push(...deleted.map((b) => b.id))
        return { count: deleted.length }
      }),
    },
    backupItem: {
      deleteMany: vi.fn().mockImplementation(async ({ where }) => {
        let deleted: Array<{ id: string; backupId: string }> = []
        if (where.backupId?.in) {
          deleted = mockState.backupItems.filter((item) =>
            where.backupId.in.includes(item.backupId)
          )
          mockState.backupItems = mockState.backupItems.filter(
            (item) => !where.backupId.in.includes(item.backupId)
          )
        }
        mockState.deletedBackupItems.push(...deleted.map((d) => d.id))
        return { count: deleted.length }
      }),
    },
  },
}))

// Mock kubeconfig verification service
vi.mock('../../../services/kubeconfig-verification.service.js', () => ({
  kubeconfigVerificationService: {
    verify: vi.fn().mockImplementation(async () => mockState.verificationResult),
  },
}))

// Import after mocking
import { ClusterService, KubeconfigVerificationError } from '../../../services/cluster.service.js'
import { prisma } from '../../../utils/prisma.js'
import { kubeconfigVerificationService } from '../../../services/kubeconfig-verification.service.js'

describe('ClusterService', () => {
  let service: ClusterService

  beforeEach(() => {
    vi.clearAllMocks()

    // Reset mock state
    mockState.clusters = [
      createMockCluster({ id: '507f1f77bcf86cd799439011', name: 'cluster-1' }),
      createMockCluster({ id: '507f1f77bcf86cd799439012', name: 'cluster-2' }),
    ]
    mockState.databases = []
    mockState.databaseAPIs = []
    mockState.backups = []
    mockState.backupItems = []
    mockState.deletedBackupItems = []
    mockState.deletedDatabaseAPIs = []
    mockState.deletedBackups = []
    mockState.deletedDatabases = []
    mockState.verificationResult = { ...sampleVerificationResult }

    service = new ClusterService()
  })

  describe('getClusters', () => {
    it('should return all clusters', async () => {
      const result = await service.getClusters()

      expect(result.data).toHaveLength(2)
      expect(result.total).toBe(2)
    })

    it('should support pagination', async () => {
      const result = await service.getClusters(false, false, 1, 10)

      expect(prisma.cluster.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: 0,
          take: 10,
        })
      )
    })

    it('should include config when withConfig=true', async () => {
      await service.getClusters(true)

      expect(prisma.cluster.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          select: expect.objectContaining({
            config: true,
          }),
        })
      )
    })

    it('should include databases when withDatabase=true', async () => {
      await service.getClusters(false, true)

      expect(prisma.cluster.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          select: expect.objectContaining({
            databases: expect.any(Object),
          }),
        })
      )
    })
  })

  describe('getClusterById', () => {
    it('should return cluster by ID', async () => {
      const result = await service.getClusterById('507f1f77bcf86cd799439011')

      expect(result).not.toBeNull()
      expect(result?.name).toBe('cluster-1')
    })

    it('should return null for non-existent cluster', async () => {
      const result = await service.getClusterById('non-existent-id')

      expect(result).toBeNull()
    })

    it('should include config when requested', async () => {
      await service.getClusterById('507f1f77bcf86cd799439011', true)

      expect(prisma.cluster.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          select: expect.objectContaining({
            config: true,
          }),
        })
      )
    })
  })

  describe('createCluster', () => {
    it('should create cluster with valid kubeconfig', async () => {
      const result = await service.createCluster({
        name: 'new-cluster',
        config: sampleKubeconfig,
      })

      expect(result.name).toBe('new-cluster')
      expect(kubeconfigVerificationService.verify).toHaveBeenCalledWith(sampleKubeconfig)
    })

    it('should throw KubeconfigVerificationError when verification fails', async () => {
      mockState.verificationResult = {
        success: false,
        cluster: null,
        user: null,
        identity: null,
        permissions: null,
        error: 'Connection refused',
      }

      await expect(
        service.createCluster({ name: 'bad-cluster', config: 'invalid' })
      ).rejects.toThrow(KubeconfigVerificationError)
    })

    it('should create cluster with databases', async () => {
      const result = await service.createCluster({
        name: 'cluster-with-db',
        config: sampleKubeconfig,
        databases: [
          {
            type: 'postgresql',
            host: 'localhost',
            port: 5432,
            username: 'admin',
            password: 'secret',
          },
        ],
      })

      expect(prisma.cluster.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            databases: expect.any(Object),
          }),
        })
      )
    })
  })

  describe('updateCluster', () => {
    it('should update cluster name', async () => {
      const result = await service.updateCluster('507f1f77bcf86cd799439011', {
        name: 'updated-cluster',
      })

      expect(result.name).toBe('updated-cluster')
    })

    it('should verify kubeconfig when config is updated', async () => {
      await service.updateCluster('507f1f77bcf86cd799439011', {
        config: sampleKubeconfig,
      })

      expect(kubeconfigVerificationService.verify).toHaveBeenCalledWith(sampleKubeconfig)
    })

    it('should not verify kubeconfig when only name is updated', async () => {
      await service.updateCluster('507f1f77bcf86cd799439011', {
        name: 'new-name',
      })

      expect(kubeconfigVerificationService.verify).not.toHaveBeenCalled()
    })

    it('should throw KubeconfigVerificationError when new config is invalid', async () => {
      mockState.verificationResult = {
        success: false,
        cluster: null,
        user: null,
        identity: null,
        permissions: null,
        error: 'Invalid config',
      }

      await expect(
        service.updateCluster('507f1f77bcf86cd799439011', { config: 'bad' })
      ).rejects.toThrow(KubeconfigVerificationError)
    })
  })

  describe('deleteCluster', () => {
    it('should delete cluster without related data', async () => {
      const result = await service.deleteCluster('507f1f77bcf86cd799439011')

      expect(result.id).toBe('507f1f77bcf86cd799439011')
      expect(mockState.clusters).toHaveLength(1)
    })

    it('should delete backups before deleting cluster', async () => {
      mockState.backups = [
        { id: 'backup-1', clusterId: '507f1f77bcf86cd799439011' },
      ]

      await service.deleteCluster('507f1f77bcf86cd799439011')

      expect(prisma.backup.deleteMany).toHaveBeenCalledWith({
        where: { clusterId: '507f1f77bcf86cd799439011' },
      })
    })

    it('should delete databases before deleting cluster', async () => {
      mockState.databases = [
        createMockDatabase('507f1f77bcf86cd799439011', { id: 'db-1' }),
      ]

      await service.deleteCluster('507f1f77bcf86cd799439011')

      expect(prisma.database.deleteMany).toHaveBeenCalledWith({
        where: { clusterId: '507f1f77bcf86cd799439011' },
      })
    })

    describe('cascade delete', () => {
      it('should delete BackupItems before Backups', async () => {
        // Setup: cluster with backups that have BackupItems
        const cascadeData = createClusterWithCascadeData()
        mockState.clusters = [cascadeData.cluster]
        mockState.databases = cascadeData.databases
        mockState.databaseAPIs = cascadeData.databaseAPIs
        mockState.backups = cascadeData.backups
        mockState.backupItems = cascadeData.backupItems

        // Should succeed after fix - BackupItems deleted first
        await service.deleteCluster(cascadeData.cluster.id)

        // Verify BackupItems were deleted
        expect(mockState.deletedBackupItems).toHaveLength(3)
        // Verify Backups were deleted
        expect(mockState.deletedBackups).toHaveLength(2)
      })

      it('should delete DatabaseAPIs before Databases', async () => {
        // Setup: cluster with databases that have APIs (no backups)
        const cascadeData = createClusterWithCascadeData()
        mockState.clusters = [cascadeData.cluster]
        mockState.databases = cascadeData.databases
        mockState.databaseAPIs = cascadeData.databaseAPIs
        mockState.backups = []
        mockState.backupItems = []

        // Should succeed after fix - DatabaseAPIs deleted first
        await service.deleteCluster(cascadeData.cluster.id)

        // Verify DatabaseAPIs were deleted
        expect(mockState.deletedDatabaseAPIs).toHaveLength(2)
        // Verify Databases were deleted
        expect(mockState.deletedDatabases).toHaveLength(2)
      })

      it('should delete all related data in correct order', async () => {
        // Setup: full cascade data
        const cascadeData = createClusterWithCascadeData()
        mockState.clusters = [cascadeData.cluster]
        mockState.databases = cascadeData.databases
        mockState.databaseAPIs = cascadeData.databaseAPIs
        mockState.backups = cascadeData.backups
        mockState.backupItems = cascadeData.backupItems

        const result = await service.deleteCluster(cascadeData.cluster.id)

        // Verify cluster was deleted
        expect(result.id).toBe(cascadeData.cluster.id)
        expect(mockState.clusters).toHaveLength(0)

        // Verify all cascade data was deleted
        expect(mockState.deletedBackupItems).toHaveLength(3)
        expect(mockState.deletedBackups).toHaveLength(2)
        expect(mockState.deletedDatabaseAPIs).toHaveLength(2)
        expect(mockState.deletedDatabases).toHaveLength(2)
      })

      it('should handle cluster with no related data', async () => {
        // Cluster with no databases, no backups
        mockState.clusters = [createMockCluster({ id: '507f1f77bcf86cd799439011' })]
        mockState.databases = []
        mockState.databaseAPIs = []
        mockState.backups = []
        mockState.backupItems = []

        const result = await service.deleteCluster('507f1f77bcf86cd799439011')

        expect(result.id).toBe('507f1f77bcf86cd799439011')
      })
    })
  })
})
