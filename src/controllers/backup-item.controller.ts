import { FastifyRequest, FastifyReply } from 'fastify'
import { backupItemService } from '../services/backup-item.service.js'
import { BackupItemCreateInput, BackupItemUpdateInput } from '../schemas/backup-item.schema.js'

export class BackupItemController {
    /**
     * Get all backup items
     */
    async getBackupItems(
        request: FastifyRequest<{ Querystring: { backupId?: string } }>,
        reply: FastifyReply
    ) {
        const { backupId } = request.query
        const backupItems = await backupItemService.getBackupItems(backupId)
        return reply.send(backupItems)
    }

    /**
     * Get backup item by ID
     */
    async getBackupItemById(
        request: FastifyRequest<{ Params: { id: string } }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const backupItem = await backupItemService.getBackupItemById(id)

        if (!backupItem) {
            return reply.status(404).send({ message: 'Backup item not found' })
        }

        return reply.send(backupItem)
    }

    /**
     * Create new backup item
     */
    async createBackupItem(
        request: FastifyRequest<{
            Params: { backupId: string }
            Body: BackupItemCreateInput
        }>,
        reply: FastifyReply
    ) {
        const { backupId } = request.params
        const backupItem = await backupItemService.createBackupItem(backupId, request.body)
        return reply.status(201).send(backupItem)
    }

    /**
     * Update backup item by ID
     */
    async updateBackupItem(
        request: FastifyRequest<{ Params: { id: string }; Body: BackupItemUpdateInput }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const backupItem = await backupItemService.updateBackupItem(id, request.body)
        return reply.send(backupItem)
    }

    /**
     * Delete backup item by ID
     */
    async deleteBackupItem(
        request: FastifyRequest<{ Params: { id: string } }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const backupItem = await backupItemService.deleteBackupItem(id)
        return reply.send(backupItem)
    }
}

export const backupItemController = new BackupItemController()
