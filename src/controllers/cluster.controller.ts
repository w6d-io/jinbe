import { FastifyReply, FastifyRequest } from 'fastify'
import { clusterService } from '../services/cluster.service.js'
import { kubeconfigVerificationService } from '../services/kubeconfig-verification.service.js'
import {
  ClusterCreateInput,
  ClusterQueryParams,
  clusterQuerySchema,
  ClusterUpdateInput,
} from '../schemas/cluster.schema.js'
import { createPaginatedResponse } from '../utils/pagination.js'

export class ClusterController {
  /**
   * Get all clusters with optional pagination
   */
  async getClusters(
    request: FastifyRequest<{ Querystring: ClusterQueryParams }>,
    reply: FastifyReply
  ) {
    const { withConfig, withDatabase, page, pageSize } =
      clusterQuerySchema.parse(request.query)
    const { data, total } = await clusterService.getClusters(
      withConfig,
      withDatabase,
      page,
      pageSize
    )

    // If pagination requested, return paginated response
    if (page && pageSize) {
      return reply.send(createPaginatedResponse(data, page, pageSize, total))
    }

    // Otherwise return simple array
    return reply.send(data)
  }

  /**
   * Get cluster by ID
   */
  async getClusterById(
    request: FastifyRequest<{
      Params: { id: string }
      Querystring: ClusterQueryParams
    }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    const { withConfig, withDatabase } = clusterQuerySchema.parse(request.query)
    const cluster = await clusterService.getClusterById(
      id,
      withConfig,
      withDatabase
    )

    if (!cluster) {
      return reply.status(404).send({ message: 'Cluster not found' })
    }

    return reply.send(cluster)
  }

  /**
   * Create new cluster
   */
  async createCluster(
    request: FastifyRequest<{ Body: ClusterCreateInput }>,
    reply: FastifyReply
  ) {
    const cluster = await clusterService.createCluster(request.body)
    return reply.status(201).send(cluster)
  }

  /**
   * Update cluster by ID
   */
  async updateCluster(
    request: FastifyRequest<{
      Params: { id: string }
      Body: ClusterUpdateInput
    }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    const cluster = await clusterService.updateCluster(id, request.body)
    return reply.send(cluster)
  }

  /**
   * Delete cluster by ID
   */
  async deleteCluster(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    const cluster = await clusterService.deleteCluster(id)
    return reply.send(cluster)
  }

  /**
   * Verify kubeconfig and retrieve token permissions/identity
   */
  async verifyKubeconfig(
    request: FastifyRequest<{ Body: { config: string } }>,
    reply: FastifyReply
  ) {
    const { config } = request.body
    const result = await kubeconfigVerificationService.verify(config)
    return reply.send(result)
  }

  /**
   * Verify kubeconfig for an existing cluster by ID
   */
  async verifyClusterConfig(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    const cluster = await clusterService.getClusterById(id, true, false)

    if (!cluster) {
      return reply.status(404).send({ message: 'Cluster not found' })
    }

    if (!cluster.config) {
      return reply.status(400).send({
        success: false,
        error: 'Cluster has no kubeconfig configured',
      })
    }

    const result = await kubeconfigVerificationService.verify(cluster.config)
    return reply.send(result)
  }
}

export const clusterController = new ClusterController()
