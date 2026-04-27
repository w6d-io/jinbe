import { FastifyRequest, FastifyReply } from 'fastify'
import { databaseService } from '../services/database.service.js'
import { DatabaseCreateInput, DatabaseUpdateInput } from '../schemas/database.schema.js'
import { PaginationQuery, createPaginatedResponse } from '../utils/pagination.js'

export class DatabaseController {
    /**
     * Get all databases (optionally filtered by clusterId, with pagination)
     */
    async getDatabases(
        request: FastifyRequest<{ 
            Querystring: { clusterId?: string } & PaginationQuery 
        }>,
        reply: FastifyReply
    ) {
        const { clusterId, page, pageSize } = request.query
        const { data, total } = await databaseService.getDatabases(clusterId, page, pageSize)
        
        // If pagination requested, return paginated response
        if (page && pageSize) {
            return reply.send(createPaginatedResponse(data, page, pageSize, total))
        }
        
        // Otherwise return simple array
        return reply.send(data)
    }

    /**
     * Get database by ID
     */
    async getDatabaseById(
        request: FastifyRequest<{ Params: { id: string } }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const database = await databaseService.getDatabaseById(id)

        if (!database) {
            return reply.status(404).send({ message: 'Database not found' })
        }

        return reply.send(database)
    }

    /**
     * Create new database
     */
    async createDatabase(
        request: FastifyRequest<{ 
            Params: { clusterId: string }
            Body: DatabaseCreateInput 
        }>,
        reply: FastifyReply
    ) {
        const { clusterId } = request.params
        const database = await databaseService.createDatabase(clusterId, request.body)
        return reply.status(201).send(database)
    }

    /**
     * Update database by ID
     */
    async updateDatabase(
        request: FastifyRequest<{ Params: { id: string }; Body: DatabaseUpdateInput }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const database = await databaseService.updateDatabase(id, request.body)
        return reply.send(database)
    }

    /**
     * Delete database by ID
     */
    async deleteDatabase(
        request: FastifyRequest<{ Params: { id: string } }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const database = await databaseService.deleteDatabase(id)
        return reply.send(database)
    }

    /**
     * List databases from the actual database server
     * Returns all databases with their roles and sizes
     */
    async listDatabasesFromServer(
        request: FastifyRequest<{ Params: { id: string } }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const databases = await databaseService.listDatabasesFromServer(id)
        return reply.send(databases)
    }
}

export const databaseController = new DatabaseController()
