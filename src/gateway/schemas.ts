import { z } from 'zod'

/**
 * Request bodies. The shape only: what each handler's config must contain is the catalog's job
 * (validate.ts), so an unknown handler or field comes back as a named issue, not a zod dump.
 */

const handlerName = z.string().regex(/^[a-z0-9_]{1,64}$/)
const handlerSpec = z.object({
  enabled: z.boolean(),
  config: z.record(z.unknown()).optional(),
}).strict()
const handlers = z.record(handlerName, handlerSpec).default({})

export const gatewaySpecSchema = z.object({
  authenticators: handlers,
  authorizers: handlers,
  mutators: handlers,
  errors: handlers,
  errorFallback: z.array(handlerName).max(8).default([]),
}).strict()

export const proposalBodySchema = z.object({
  spec: gatewaySpecSchema,
  note: z.string().max(500).optional(),
}).strict()

export const rollbackBodySchema = z.object({ note: z.string().max(500).optional() }).strict().default({})

export type ProposalBody = z.infer<typeof proposalBodySchema>
