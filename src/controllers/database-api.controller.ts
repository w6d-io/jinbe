import { FastifyRequest, FastifyReply } from 'fastify'
import { databaseAPIService } from '../services/database-api.service.js'
import { DatabaseAPICreateInput, DatabaseAPIUpdateInput } from '../schemas/database-api.schema.js'

export class DatabaseAPIController {
    /**
     * Get all database APIs
     */
    async getDatabaseAPIs(_request: FastifyRequest, reply: FastifyReply) {
        const databaseAPIs = await databaseAPIService.getDatabaseAPIs()
        return reply.send(databaseAPIs)
    }

    /**
     * Get database API by ID
     */
    async getDatabaseAPIById(
        request: FastifyRequest<{ Params: { id: string } }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const databaseAPI = await databaseAPIService.getDatabaseAPIById(id)

        if (!databaseAPI) {
            return reply.status(404).send({ message: 'Database API not found' })
        }

        return reply.send(databaseAPI)
    }

    /**
     * Get database API by database ID
     */
    async getDatabaseAPIByDatabaseId(
        request: FastifyRequest<{ Params: { databaseId: string } }>,
        reply: FastifyReply
    ) {
        const { databaseId } = request.params
        const databaseAPI = await databaseAPIService.getDatabaseAPIByDatabaseId(databaseId)

        if (!databaseAPI) {
            return reply.status(404).send({ message: 'Database API not found for this database' })
        }

        return reply.send(databaseAPI)
    }

    /**
     * Create new database API
     */
    async createDatabaseAPI(
        request: FastifyRequest<{
            Params: { databaseId: string }
            Body: DatabaseAPICreateInput
        }>,
        reply: FastifyReply
    ) {
        const { databaseId } = request.params
        const databaseAPI = await databaseAPIService.createDatabaseAPI(databaseId, request.body)
        return reply.status(201).send(databaseAPI)
    }

    /**
     * Update database API by ID
     */
    async updateDatabaseAPI(
        request: FastifyRequest<{ Params: { id: string }; Body: DatabaseAPIUpdateInput }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const databaseAPI = await databaseAPIService.updateDatabaseAPI(id, request.body)
        return reply.send(databaseAPI)
    }

    /**
     * Delete database API by ID
     */
    async deleteDatabaseAPI(
        request: FastifyRequest<{ Params: { id: string } }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const databaseAPI = await databaseAPIService.deleteDatabaseAPI(id)
        return reply.send(databaseAPI)
    }
}

export const databaseAPIController = new DatabaseAPIController()
