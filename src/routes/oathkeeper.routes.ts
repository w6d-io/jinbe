import type { FastifyInstance } from 'fastify'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'

/**
 * Oathkeeper Rules endpoint — polled by Oathkeeper
 *
 * GET /api/oathkeeper/rules → JSON array of access rules
 * Oathkeeper config: access_rules.repositories = ["http://jinbe:8080/api/oathkeeper/rules"]
 * Public — no auth required (internal cluster only)
 */
export async function oathkeeperRoutes(fastify: FastifyInstance) {
  fastify.get('/rules', {
    schema: {
      description: 'Get Oathkeeper access rules. Polled by Oathkeeper.',
      tags: ['oathkeeper'],
      // No response schema — Oathkeeper rules have dynamic structure
      // Fastify's default serialization strips unknown properties with strict schemas
    },
  }, async (_request, reply) => {
    const rules = await redisRbacRepository.getAccessRules()
    return reply.send(rules)
  })
}
