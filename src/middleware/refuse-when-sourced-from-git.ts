import { FastifyRequest, FastifyReply } from 'fastify'
import { env } from '../config/env.js'

/**
 * Refuse a write to something the repository owns.
 *
 * `RULES_SOURCE=gitops` says the edge rules and the policy data are rendered from Git and synced by
 * a controller. In that mode this service is not their source: a write here lands in a store nothing
 * reads, reports success, and is then reverted by the next sync — invisibly, because nothing
 * compares the two.
 *
 * The flag existed before this and gated NOTHING. It was reported to the console, which greys its
 * editors and says why; but the console was the only caller that honoured it. Anything else holding
 * an admin session — a script, a stale tab, a second console — still wrote.
 *
 * 409 rather than 403: the caller is not lacking a right. Nobody has this one, the super admin
 * included, because the authority moved to the repository. A 403 would send somebody looking for a
 * permission to grant themselves.
 */
export async function refuseWhenSourcedFromGit(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (env.RULES_SOURCE !== 'gitops') return

  request.log.info(
    { path: request.url, method: request.method, actor: request.userContext?.email },
    'refused a write to an artefact the repository owns',
  )

  await reply.status(409).send({
    error: 'Conflict',
    message:
      'This deployment renders its rules and policy data from Git, so this service cannot change ' +
      'them. Change them in the repository; Argo syncs them, and the APIs screen shows what is in ' +
      'force.',
    rulesSource: env.RULES_SOURCE,
  })
}
