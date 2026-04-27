import { FastifyRequest, FastifyReply } from 'fastify'
import { backupService } from '../services/backup.service.js'
import { BackupCreateInput } from '../schemas/backup.schema.js'

export class BackupController {
    /**
     * Get all backups
     */
    async getBackups(
        request: FastifyRequest<{ Querystring: { clusterId?: string } }>,
        reply: FastifyReply
    ) {
        const { clusterId } = request.query
        const backups = await backupService.getBackups(clusterId)
        return reply.send(backups)
    }

    /**
     * Get backup by ID
     */
    async getBackupById(
        request: FastifyRequest<{ Params: { id: string } }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const backup = await backupService.getBackupById(id)

        if (!backup) {
            return reply.status(404).send({ message: 'Backup not found' })
        }

        return reply.send(backup)
    }

    /**
     * Create new backup
     */
    async createBackup(
        request: FastifyRequest<{
            Params: { clusterId: string }
            Body: BackupCreateInput
        }>,
        reply: FastifyReply
    ) {
        const { clusterId } = request.params
        const backup = await backupService.createBackup(clusterId, request.body)
        return reply.status(201).send(backup)
    }

    /**
     * Delete backup by ID
     */
    async deleteBackup(
        request: FastifyRequest<{ Params: { id: string } }>,
        reply: FastifyReply
    ) {
        const { id } = request.params
        const backup = await backupService.deleteBackup(id)
        return reply.send(backup)
    }
}

export const backupController = new BackupController()
