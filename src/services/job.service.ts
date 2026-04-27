import { createJob, getJobsInfo, getBackupPods } from '../k8s/job.js'
import type { CreateJobRequest, JobInfo } from '../schemas/job.schema.js'
import prisma from '../lib/prisma.js'

export class JobService {
    async getClusterNameById(clusterId: string): Promise<string> {
        const cluster = await prisma.cluster.findUnique({
            where: { id: clusterId },
            select: { name: true },
        })
        if (!cluster) {
            throw new Error(`Cluster with id "${clusterId}" not found`)
        }
        return cluster.name
    }

    async createBackupRestoreJob(
        clusterId: string,
        data: CreateJobRequest
    ): Promise<true | string> {
        const clusterName = await this.getClusterNameById(clusterId)
        // Default to current date if not provided (typically for backup)
        const jobDate = data.date ?? new Date()
        return createJob(
            data.database_type,
            data.action,
            clusterName,
            jobDate,
            data.bases
        )
    }

    async getJobs(clusterId: string, namespace: string = 'default'): Promise<JobInfo[]> {
        const clusterName = await this.getClusterNameById(clusterId)
        return getJobsInfo(namespace, clusterName)
    }

    async getJobPods(clusterId: string, namespace: string = 'default') {
        const clusterName = await this.getClusterNameById(clusterId)
        return getBackupPods(namespace, clusterName)
    }
}

export const jobService = new JobService()
