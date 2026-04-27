import { FastifyRequest, FastifyReply } from 'fastify'
import { jobService } from '../services/job.service.js'
import {
    createJobRequestSchema,
    getJobsQuerySchema,
    type CreateJobRequest,
    type GetJobsQuery,
} from '../schemas/job.schema.js'

export class JobController {
    /**
     * Create a backup or restore job
     */
    async createJob(
        request: FastifyRequest<{
            Params: { clusterId: string }
            Body: CreateJobRequest
        }>,
        reply: FastifyReply
    ) {
        const { clusterId } = request.params
        const data = createJobRequestSchema.parse(request.body)
        const result = await jobService.createBackupRestoreJob(clusterId, data)

        if (result === true) {
            return reply.status(201).send({ success: true, message: 'Job created successfully' })
        }

        return reply.status(400).send({ success: false, error: result })
    }

    /**
     * List jobs for a cluster
     */
    async getJobs(
        request: FastifyRequest<{
            Params: { clusterId: string }
            Querystring: GetJobsQuery
        }>,
        reply: FastifyReply
    ) {
        const { clusterId } = request.params
        const { namespace } = getJobsQuerySchema.parse(request.query)
        const jobs = await jobService.getJobs(clusterId, namespace)
        return reply.send(jobs)
    }

    /**
     * Get pods for backup/restore jobs
     */
    async getJobPods(
        request: FastifyRequest<{
            Params: { clusterId: string }
            Querystring: GetJobsQuery
        }>,
        reply: FastifyReply
    ) {
        const { clusterId } = request.params
        const { namespace } = getJobsQuerySchema.parse(request.query)
        const pods = await jobService.getJobPods(clusterId, namespace)
        return reply.send(pods)
    }
}

export const jobController = new JobController()
