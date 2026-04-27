import { prisma } from '../utils/prisma.js'
import { ClusterCreateInput, ClusterUpdateInput } from '../schemas/cluster.schema.js'
import { getPaginationParams } from '../utils/pagination.js'
import {
  kubeconfigVerificationService,
  KubeconfigVerificationResult,
} from './kubeconfig-verification.service.js'

/**
 * Error thrown when kubeconfig verification fails
 */
export class KubeconfigVerificationError extends Error {
  constructor(
    message: string,
    public verificationResult: KubeconfigVerificationResult
  ) {
    super(message)
    this.name = 'KubeconfigVerificationError'
  }
}

export class ClusterService {
    /**
     * Get all clusters with optional pagination
     */
    async getClusters(
        withConfig = false,
        withDatabase = false,
        page?: number,
        pageSize?: number
    ) {
        const select = {
            id: true,
            name: true,
            config: withConfig,
            createdAt: true,
            updatedAt: true,
            databases: withDatabase
                ? {
                      select: {
                          id: true,
                          type: true,
                          host: true,
                          port: true,
                          username: true,
                      },
                  }
                : false,
            _count: {
                select: {
                    databases: true,
                    backups: true,
                },
            },
        }

        // If pagination params provided, use them
        if (page && pageSize) {
            const { skip, take } = getPaginationParams(page, pageSize)
            
            const [clusters, total] = await Promise.all([
                prisma.cluster.findMany({ select, skip, take }),
                prisma.cluster.count(),
            ])
            
            return { data: clusters, total }
        }

        // Otherwise return all
        const clusters = await prisma.cluster.findMany({ select })
        return { data: clusters, total: clusters.length }
    }

    /**
     * Get cluster by ID
     */
    async getClusterById(id: string, withConfig = false, withDatabase = false) {
        const cluster = await prisma.cluster.findUnique({
            where: { id },
            select: {
                id: true,
                name: true,
                config: withConfig,
                createdAt: true,
                updatedAt: true,
                databases: withDatabase
                    ? {
                          select: {
                              id: true,
                              type: true,
                              host: true,
                              port: true,
                              username: true,
                          },
                      }
                    : false,
                _count: {
                    select: {
                        databases: true,
                        backups: true,
                    },
                },
            },
        })
        return cluster
    }

    /**
     * Create new cluster
     */
    async createCluster(clusterData: ClusterCreateInput) {
        // Verify kubeconfig before creating cluster
        if (clusterData.config) {
            const verificationResult = await kubeconfigVerificationService.verify(
                clusterData.config
            )
            if (!verificationResult.success) {
                throw new KubeconfigVerificationError(
                    `Kubeconfig verification failed: ${verificationResult.error}`,
                    verificationResult
                )
            }
        }

        const cluster = await prisma.cluster.create({
            data: {
                name: clusterData.name,
                config: clusterData.config,
                databases: clusterData.databases
                    ? {
                          create: clusterData.databases.map((db) => ({
                              ...db,
                              api: db.api ? { create: db.api } : undefined,
                          })),
                      }
                    : undefined,
            },
            select: {
                id: true,
                name: true,
                config: true,
                createdAt: true,
                updatedAt: true,
                databases: {
                    select: {
                        id: true,
                        type: true,
                        host: true,
                        port: true,
                        username: true,
                    },
                },
            },
        })
        return cluster
    }

    /**
     * Update cluster by ID
     */
    async updateCluster(id: string, clusterData: ClusterUpdateInput) {
        // Verify kubeconfig before updating cluster (only if config is being updated)
        if (clusterData.config) {
            const verificationResult = await kubeconfigVerificationService.verify(
                clusterData.config
            )
            if (!verificationResult.success) {
                throw new KubeconfigVerificationError(
                    `Kubeconfig verification failed: ${verificationResult.error}`,
                    verificationResult
                )
            }
        }

        const cluster = await prisma.cluster.update({
            where: { id },
            data: {
                name: clusterData.name,
                config: clusterData.config,
                updatedAt: new Date(),
            },
            select: {
                id: true,
                name: true,
                config: true,
                createdAt: true,
                updatedAt: true,
                databases: {
                    select: {
                        id: true,
                        type: true,
                        host: true,
                        port: true,
                        username: true,
                    },
                },
            },
        })
        return cluster
    }

    /**
     * Delete cluster by ID
     * Performs cascade delete in correct order:
     * 1. BackupItems (reference Backups)
     * 2. Backups (reference Cluster)
     * 3. DatabaseAPIs (reference Databases)
     * 4. Databases (reference Cluster)
     * 5. Cluster
     */
    async deleteCluster(id: string) {
        // Step 1: Get all backup IDs for this cluster
        const backups = await prisma.backup.findMany({
            where: { clusterId: id },
            select: { id: true },
        })
        const backupIds = backups.map((b) => b.id)

        // Step 2: Delete BackupItems that reference these backups
        if (backupIds.length > 0) {
            await prisma.backupItem.deleteMany({
                where: { backupId: { in: backupIds } },
            })
        }

        // Step 3: Delete Backups
        await prisma.backup.deleteMany({
            where: { clusterId: id },
        })

        // Step 4: Get all database IDs for this cluster
        const databases = await prisma.database.findMany({
            where: { clusterId: id },
            select: { id: true },
        })
        const databaseIds = databases.map((d) => d.id)

        // Step 5: Delete DatabaseAPIs that reference these databases
        if (databaseIds.length > 0) {
            await prisma.databaseAPI.deleteMany({
                where: { databaseId: { in: databaseIds } },
            })
        }

        // Step 6: Delete Databases
        await prisma.database.deleteMany({
            where: { clusterId: id },
        })

        // Step 7: Now delete the cluster
        const cluster = await prisma.cluster.delete({
            where: { id },
            select: {
                id: true,
                name: true,
                config: true,
                createdAt: true,
                updatedAt: true,
            },
        })
        return cluster
    }
}

export const clusterService = new ClusterService()
