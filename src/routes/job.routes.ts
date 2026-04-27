import { FastifyInstance } from 'fastify'
import { zodToJsonSchema } from 'zod-to-json-schema'
import { jobController } from '../controllers/job.controller.js'
import {
    createJobRequestSchema,
    getJobsQuerySchema,
} from '../schemas/job.schema.js'
import {
    notFoundResponseSchema,
    unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'
import { z } from 'zod'

const clusterIdParamSchema = z.object({
    clusterId: z.string().length(24, 'Invalid ObjectId'),
})

const jobCreateResponseSchema = {
    type: 'object',
    properties: {
        success: { type: 'boolean' },
        message: { type: 'string' },
    },
}

const jobErrorResponseSchema = {
    type: 'object',
    properties: {
        success: { type: 'boolean' },
        error: { type: 'string' },
    },
}

const jobInfoJsonSchema = {
    type: 'object',
    properties: {
        database_type: { type: 'string' },
        name: { type: 'string' },
        timestamp: { type: 'string' },
        status: {
            type: 'string',
            enum: ['pending', 'running', 'completed', 'failed', 'Unknown'],
        },
        age: { type: 'string' },
        namespace: { type: 'string' },
        creationTimestamp: { type: 'string', format: 'date-time' },
    },
}

export async function jobRoutes(fastify: FastifyInstance) {
    // Create a backup or restore job
    fastify.post(
        '/clusters/:clusterId/jobs',
        {
            schema: {
                description: 'Create a backup or restore job for a cluster',
                tags: ['jobs'],
                params: zodToJsonSchema(clusterIdParamSchema),
                body: zodToJsonSchema(createJobRequestSchema),
                response: {
                    201: jobCreateResponseSchema,
                    400: jobErrorResponseSchema,
                    401: unauthorizedResponseSchema,
                    404: notFoundResponseSchema,
                },
            },
        },
        jobController.createJob.bind(jobController)
    )

    // List jobs for a cluster
    fastify.get(
        '/clusters/:clusterId/jobs',
        {
            schema: {
                description: 'List all backup/restore jobs for a cluster',
                tags: ['jobs'],
                params: zodToJsonSchema(clusterIdParamSchema),
                querystring: zodToJsonSchema(getJobsQuerySchema),
                response: {
                    200: {
                        type: 'array',
                        items: jobInfoJsonSchema,
                    },
                    401: unauthorizedResponseSchema,
                    404: notFoundResponseSchema,
                },
            },
        },
        jobController.getJobs.bind(jobController)
    )

    // Get pods for backup/restore jobs
    fastify.get(
        '/clusters/:clusterId/jobs/pods',
        {
            schema: {
                description: 'Get pods for backup/restore jobs in a cluster',
                tags: ['jobs'],
                params: zodToJsonSchema(clusterIdParamSchema),
                querystring: zodToJsonSchema(getJobsQuerySchema),
                response: {
                    200: {
                        type: 'array',
                        items: { type: 'object', additionalProperties: true },
                    },
                    401: unauthorizedResponseSchema,
                    404: notFoundResponseSchema,
                },
            },
        },
        jobController.getJobPods.bind(jobController)
    )
}
