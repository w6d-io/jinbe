import { z } from 'zod'
import { accessSchema } from '../schemas.js'
import { LIMITS } from './limits.js'

/** Request bodies of /api/admin/sites/:name/import/{preview,commit}, validated here only. */

const paramName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/, 'a path parameter name')
const routeId = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/, 'lowercase letters, digits and dashes')
const permission = z.string().max(128).regex(/^[a-z][a-z0-9_.-]*:[a-z*][a-z0-9_*-]*$/, 'a permission like resource:verb')

export const importOptionsSchema = z
  .object({
    basePath: z.string().max(256).regex(/^(\/[A-Za-z0-9._~@-]+)*$/, "a literal path like /api/v1, or '' for none").optional(),
    basePathMode: z.enum(['prepend', 'strip', 'none']).default('prepend'),
    resourceFrom: z.enum(['tag', 'path', 'operationId']).default('tag'),
    listAsRead: z.boolean().default(false),
    scopeMap: z.record(z.string().min(1).max(256), permission).refine((m) => Object.keys(m).length <= 256, 'at most 256 scopes').optional(),
    orgParam: paramName.optional(),
    defaultGate: routeId.optional(),
  })
  .strict()
  .default({})

export const decisionSchema = z
  .object({
    op: z.string().min(1).max(600),
    access: accessSchema.optional(),
    gate: routeId.optional(),
    orgParam: paramName.nullable().optional(),
    skip: z.boolean().optional(),
    remove: z.boolean().optional(),
    /**
     * Required for what lowers protection (public, signed-in, an organization parameter removed) and
     * for every high-risk row the preview marks `needsConfirm`. Alone, it changes nothing.
     */
    confirm: z.boolean().optional(),
  })
  .strict()

const decisions = z
  .array(decisionSchema)
  .max(LIMITS.operations)
  .refine((d) => new Set(d.map((x) => x.op)).size === d.length, 'one decision per operation')
  .default([])

export const importPreviewBodySchema = z
  .object({
    source: z.union([
      z.object({ content: z.string().min(1).max(LIMITS.bytes), format: z.enum(['auto', 'json', 'yaml']).default('auto') }).strict(),
      // Fetching by URL comes with its SSRF fence (W3); until then it is refused.
      z.object({ url: z.string().min(1).max(2048) }).strict(),
    ]),
    options: importOptionsSchema,
    decisions,
  })
  .strict()

export const importCommitBodySchema = z
  .object({
    specSha256: z.string().regex(/^[a-f0-9]{64}$/, 'the sha256 the preview answered'),
    baseEtag: z.string().regex(/^[a-f0-9]{16}$/, 'the base etag the preview answered'),
    options: importOptionsSchema,
    decisions,
    /** Leave every operation no permission could be derived for denied, instead of deciding each. */
    acceptDenied: z.boolean().default(false),
  })
  .strict()

export type ImportPreviewBody = z.infer<typeof importPreviewBodySchema>
export type ImportCommitBody = z.infer<typeof importCommitBodySchema>
