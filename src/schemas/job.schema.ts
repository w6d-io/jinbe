import { z } from 'zod'

export const databaseSelectedSchema = z.object({
    database: z.string(),
    size: z.number().optional().default(0),
    username: z.string(),
    adminUsername: z.string(),
})

export type DatabaseSelected = z.infer<typeof databaseSelectedSchema>

export const jobInfoSchema = z.object({
    database_type: z.string(),
    name: z.string(),
    timestamp: z.string(),
    status: z.enum(['pending', 'running', 'completed', 'failed', 'Unknown']),
    age: z.string(),
    namespace: z.string(),
    creationTimestamp: z.coerce.date(),
})

export type JobInfo = z.infer<typeof jobInfoSchema>

export const createJobRequestSchema = z.object({
    database_type: z.enum(['postgresql', 'mongodb']),
    action: z.enum(['backup', 'restore']),
    date: z.coerce.date().optional(), // Optional - defaults to current date for backup, required for restore
    bases: z.array(databaseSelectedSchema),
})

export type CreateJobRequest = z.infer<typeof createJobRequestSchema>

export const getJobsQuerySchema = z.object({
    namespace: z.string().optional().default('default'),
})

export type GetJobsQuery = z.infer<typeof getJobsQuerySchema>
