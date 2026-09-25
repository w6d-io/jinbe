import type { FastifyInstance, FastifyBaseLogger } from 'fastify'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { rulesGenerated, ruleCompileErrors } from '../telemetry/metrics.js'

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
  }, async (request, reply) => {
    const rules = await redisRbacRepository.getAccessRules()
    recordRuleSet(rules as Array<{ id?: string; match?: { url?: string } }>, request.log)
    return reply.send(rules)
  })
}

/**
 * The ids of rules whose match URL would not compile under Oathkeeper's regexp strategy. Oathkeeper
 * refuses the WHOLE rule set when one rule fails, so a single `<**>` (glob syntax) takes every site
 * behind the gateway down. JavaScript's RegExp stands in for Go's RE2 here: close enough to catch
 * that class of mistake, not a proof of the reverse.
 */
export function uncompilableRules(rules: Array<{ id?: string; match?: { url?: string } }>): string[] {
  const bad: string[] = []
  for (const rule of rules) {
    for (const [, inner] of (rule.match?.url ?? '').matchAll(/<([^<>]*)>/g)) {
      try {
        new RegExp(`^${inner}$`)
      } catch {
        bad.push(rule.id ?? '?')
        break
      }
    }
  }
  return bad
}

let lastBad = ''

function recordRuleSet(rules: Array<{ id?: string; match?: { url?: string } }>, log: FastifyBaseLogger) {
  const bad = uncompilableRules(rules)
  rulesGenerated.set(rules.length)
  ruleCompileErrors.set(bad.length)
  // Polled every few seconds: say it when the set of broken rules changes, not on every poll.
  const key = bad.join(',')
  if (key !== lastBad) {
    lastBad = key
    if (bad.length > 0) log.warn({ rules: bad }, 'access rules that will not compile under the regexp strategy')
  }
}
