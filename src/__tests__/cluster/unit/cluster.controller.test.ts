import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'
import {
  createMockCluster,
  sampleVerificationResult,
} from '../fixtures/cluster.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  clusters: [] as Array<{
    id: string
    name: string
    config: string
    createdAt: Date
    updatedAt: Date
  }>,
  verificationResult: {
    success: true,
    cluster: { name: 'test', server: 'https://k8s.example.com' },
    user: { name: 'test', authMethod: 'token' as const },
    identity: null,
    permissions: null,
  },
}))

// Mock cluster service
vi.mock('../../../services/cluster.service.js', () => ({
  clusterService: {
    getClusters: vi.fn().mockImplementation(async () => ({
      data: mockState.clusters,
      total: mockState.clusters.length,
    })),
    getClusterById: vi.fn().mockImplementation(async (id: string) => {
      return mockState.clusters.find((c) => c.id === id) || null
    }),
    createCluster: vi.fn().mockImplementation(async (data: { name: string; config: string }) => ({
      id: '507f1f77bcf86cd799439099',
      name: data.name,
      config: data.config,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    updateCluster: vi.fn().mockImplementation(async (id: string, data: object) => {
      const cluster = mockState.clusters.find((c) => c.id === id)
      if (!cluster) throw new Error('Not found')
      return { ...cluster, ...data }
    }),
    deleteCluster: vi.fn().mockImplementation(async (id: string) => {
      const cluster = mockState.clusters.find((c) => c.id === id)
      if (!cluster) throw new Error('Not found')
      return cluster
    }),
  },
}))

// Mock kubeconfig verification service
vi.mock('../../../services/kubeconfig-verification.service.js', () => ({
  kubeconfigVerificationService: {
    verify: vi.fn().mockImplementation(async () => mockState.verificationResult),
  },
}))

// Import after mocking
import { ClusterController } from '../../../controllers/cluster.controller.js'
import { clusterService } from '../../../services/cluster.service.js'
import { kubeconfigVerificationService } from '../../../services/kubeconfig-verification.service.js'

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

describe('ClusterController', () => {
  let controller: ClusterController

  beforeEach(() => {
    vi.clearAllMocks()

    mockState.clusters = [
      createMockCluster({ id: '507f1f77bcf86cd799439011', name: 'cluster-1' }),
      createMockCluster({ id: '507f1f77bcf86cd799439012', name: 'cluster-2' }),
    ]
    mockState.verificationResult = { ...sampleVerificationResult }

    controller = new ClusterController()
  })

  describe('getClusters', () => {
    it('should return list of clusters', async () => {
      const request = createMockRequest({ query: {} })
      const reply = createMockReply()

      await controller.getClusters(request as FastifyRequest<{ Querystring: object }>, reply)

      expect(reply._body).toHaveLength(2)
    })

    it('should return paginated response when page params provided', async () => {
      const request = createMockRequest({ query: { page: '1', pageSize: '10' } })
      const reply = createMockReply()

      await controller.getClusters(request as FastifyRequest<{ Querystring: object }>, reply)

      expect(clusterService.getClusters).toHaveBeenCalledWith(undefined, undefined, 1, 10)
    })

    it('should pass withConfig and withDatabase flags', async () => {
      const request = createMockRequest({
        query: { withConfig: 'true', withDatabase: 'true' },
      })
      const reply = createMockReply()

      await controller.getClusters(request as FastifyRequest<{ Querystring: object }>, reply)

      expect(clusterService.getClusters).toHaveBeenCalledWith(true, true, undefined, undefined)
    })
  })

  describe('getClusterById', () => {
    it('should return cluster by ID', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439011' },
        query: {},
      })
      const reply = createMockReply()

      await controller.getClusterById(
        request as FastifyRequest<{ Params: { id: string }; Querystring: object }>,
        reply
      )

      expect(reply._body).toBeDefined()
      expect((reply._body as { id: string }).id).toBe('507f1f77bcf86cd799439011')
    })

    it('should return 404 when cluster not found', async () => {
      const request = createMockRequest({
        params: { id: 'non-existent' },
        query: {},
      })
      const reply = createMockReply()

      await controller.getClusterById(
        request as FastifyRequest<{ Params: { id: string }; Querystring: object }>,
        reply
      )

      expect(reply._statusCode).toBe(404)
      expect((reply._body as { message: string }).message).toBe('Cluster not found')
    })
  })

  describe('createCluster', () => {
    it('should create cluster and return 201', async () => {
      const request = createMockRequest({
        body: { name: 'new-cluster', config: 'kubeconfig-content' },
      })
      const reply = createMockReply()

      await controller.createCluster(
        request as FastifyRequest<{ Body: { name: string; config: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(201)
      expect(reply._body).toBeDefined()
    })

    it('should call clusterService.createCluster with body', async () => {
      const clusterData = { name: 'test-cluster', config: 'kubeconfig' }
      const request = createMockRequest({ body: clusterData })
      const reply = createMockReply()

      await controller.createCluster(
        request as FastifyRequest<{ Body: typeof clusterData }>,
        reply
      )

      expect(clusterService.createCluster).toHaveBeenCalledWith(clusterData)
    })
  })

  describe('updateCluster', () => {
    it('should update cluster', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439011' },
        body: { name: 'updated-name' },
      })
      const reply = createMockReply()

      await controller.updateCluster(
        request as FastifyRequest<{ Params: { id: string }; Body: { name: string } }>,
        reply
      )

      expect(reply._body).toBeDefined()
      expect(clusterService.updateCluster).toHaveBeenCalledWith(
        '507f1f77bcf86cd799439011',
        { name: 'updated-name' }
      )
    })
  })

  describe('deleteCluster', () => {
    it('should delete cluster', async () => {
      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439011' },
      })
      const reply = createMockReply()

      await controller.deleteCluster(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._body).toBeDefined()
      expect(clusterService.deleteCluster).toHaveBeenCalledWith('507f1f77bcf86cd799439011')
    })
  })

  describe('verifyKubeconfig', () => {
    it('should verify kubeconfig and return result', async () => {
      const request = createMockRequest({
        body: { config: 'kubeconfig-content' },
      })
      const reply = createMockReply()

      await controller.verifyKubeconfig(
        request as FastifyRequest<{ Body: { config: string } }>,
        reply
      )

      expect(reply._body).toEqual(mockState.verificationResult)
      expect(kubeconfigVerificationService.verify).toHaveBeenCalledWith('kubeconfig-content')
    })
  })

  describe('verifyClusterConfig', () => {
    it('should verify existing cluster config', async () => {
      // Add config to mock cluster
      mockState.clusters[0].config = 'cluster-kubeconfig'

      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439011' },
      })
      const reply = createMockReply()

      await controller.verifyClusterConfig(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(kubeconfigVerificationService.verify).toHaveBeenCalledWith('cluster-kubeconfig')
    })

    it('should return 404 when cluster not found', async () => {
      const request = createMockRequest({
        params: { id: 'non-existent' },
      })
      const reply = createMockReply()

      await controller.verifyClusterConfig(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(404)
    })

    it('should return 400 when cluster has no config', async () => {
      // Remove config from mock cluster
      mockState.clusters[0].config = ''

      const request = createMockRequest({
        params: { id: '507f1f77bcf86cd799439011' },
      })
      const reply = createMockReply()

      await controller.verifyClusterConfig(
        request as FastifyRequest<{ Params: { id: string } }>,
        reply
      )

      expect(reply._statusCode).toBe(400)
      expect((reply._body as { error: string }).error).toContain('no kubeconfig')
    })
  })
})
