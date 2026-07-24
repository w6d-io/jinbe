// OpenAPI import orchestrator: parse a spec → derive a permission per operation
// → diff against the live route_map → return a reviewable preview. Pure analysis;
// it never writes. Apply is the existing PUT /services/:name/routes.

import SwaggerParser from '@apidevtools/swagger-parser'
import { parse as parseYaml } from 'yaml'
import { redisRbacRepository } from '../redis-rbac.repository.js'
import {
  derivePermission,
  openApiPathToRoute,
  DEFAULT_VERB_MAP,
  type DerivationOptions,
} from './derivation.js'
import { diffRoutes, type DerivedRoute, type RouteDiff } from './diff.js'

const HTTP_METHODS = ['get', 'put', 'post', 'delete', 'patch', 'head', 'options'] as const

export interface ImportSource {
  url?: string
  content?: string
  format?: 'json' | 'yaml' | 'auto'
}

export interface ImportOptions extends Partial<DerivationOptions> {
  basePath?: 'prepend' | 'strip' | 'none'
}

export interface PreviewWarning {
  kind: 'orphan_permission' | 'unmapped' | 'catchall_removed'
  message: string
  detail?: string
}

export interface PreviewResult {
  service: string
  detectedBasePath: string
  basePathMode: 'prepend' | 'strip' | 'none'
  operationCount: number
  derived: DerivedRoute[]
  diff: RouteDiff
  warnings: PreviewWarning[]
}

function detectBasePath(api: any): string {
  if (typeof api.basePath === 'string') return api.basePath.replace(/\/$/, '') // Swagger 2.0
  const url = api.servers?.[0]?.url
  if (typeof url === 'string') {
    if (url.startsWith('/')) return url.replace(/\/$/, '') // relative server url
    try {
      return new URL(url).pathname.replace(/\/$/, '') // absolute → path component
    } catch {
      return ''
    }
  }
  return ''
}

async function loadSpec(source: ImportSource): Promise<any> {
  if (source.content && source.content.trim()) {
    const txt = source.content
    const fmt = source.format ?? 'auto'
    const obj =
      fmt === 'json' || (fmt === 'auto' && txt.trimStart().startsWith('{'))
        ? JSON.parse(txt)
        : parseYaml(txt)
    return SwaggerParser.dereference(obj)
  }
  if (source.url && source.url.trim()) {
    return SwaggerParser.dereference(source.url.trim())
  }
  throw new Error('provide source.url or source.content')
}

export async function previewImport(
  service: string,
  source: ImportSource,
  options: ImportOptions,
): Promise<PreviewResult> {
  const opts: DerivationOptions = {
    resourceFrom: options.resourceFrom ?? 'tag',
    verbMap: { ...DEFAULT_VERB_MAP, ...(options.verbMap ?? {}) },
    listAsRead: options.listAsRead ?? false,
    honorExtension: options.honorExtension ?? true,
    scopeMap: options.scopeMap,
  }
  const basePathMode = options.basePath ?? 'prepend'

  if (!(await redisRbacRepository.serviceExists(service))) {
    const err: any = new Error(`Unknown service: ${service}`)
    err.statusCode = 404
    err.code = 'service_not_found'
    throw err
  }

  let api: any
  try {
    api = await loadSpec(source)
  } catch (e: any) {
    const err: any = new Error(`Could not parse the OpenAPI spec: ${e?.message ?? e}`)
    err.statusCode = 422
    err.code = 'invalid_spec'
    throw err
  }

  const detectedBasePath = detectBasePath(api)
  const derived: DerivedRoute[] = []
  const paths = api.paths ?? {}

  for (const [specPath, item] of Object.entries<any>(paths)) {
    if (!item || typeof item !== 'object') continue
    const routePath = openApiPathToRoute(specPath, detectedBasePath, basePathMode)
    const lastSeg = routePath.split('/').filter(Boolean).pop() ?? ''
    const isCollection = !lastSeg.startsWith(':')
    for (const m of HTTP_METHODS) {
      const op = item[m]
      if (!op || typeof op !== 'object') continue
      const extensions: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(op)) if (k.startsWith('x-')) extensions[k] = v
      const d = derivePermission(
        {
          method: m.toUpperCase(),
          routePath,
          operationId: op.operationId,
          tags: op.tags,
          security: op.security ?? api.security,
          extensions,
          isCollection,
        },
        opts,
      )
      derived.push({
        method: m.toUpperCase(),
        path: routePath,
        permission: d.permission,
        public: d.public,
        source: d.source,
        operationId: op.operationId,
        summary: op.summary,
      })
    }
  }

  const current = (await redisRbacRepository.getRouteMap(service))?.rules ?? []
  const diff = diffRoutes(derived, current)

  const warnings: PreviewWarning[] = []
  const unmapped = derived.filter((d) => d.source === 'unmapped')
  if (unmapped.length) {
    warnings.push({ kind: 'unmapped', message: `${unmapped.length} operation(s) need a permission chosen before import.` })
  }
  const catchalls = diff.stale.filter((s) => s.isCatchall)
  if (catchalls.length) {
    warnings.push({
      kind: 'catchall_removed',
      message: `${catchalls.length} catch-all rule(s) will be removed (fail-open surfaces).`,
      detail: catchalls.map((c) => `${c.method} ${c.path}`).join(', '),
    })
  }
  const grantable = await grantablePermissions(service)
  if (grantable !== '*') {
    const orphans = new Set<string>()
    for (const d of derived) if (d.permission && !grantable.has(d.permission)) orphans.add(d.permission)
    if (orphans.size) {
      warnings.push({
        kind: 'orphan_permission',
        message: `${orphans.size} derived permission(s) are granted by no role yet — nobody can reach those routes until a role grants them.`,
        detail: [...orphans].join(', '),
      })
    }
  }

  return { service, detectedBasePath, basePathMode, operationCount: derived.length, derived, diff, warnings }
}

/** Union of permissions any role (service + global) grants; '*' short-circuits. */
async function grantablePermissions(service: string): Promise<Set<string> | '*'> {
  const set = new Set<string>()
  for (const svc of [service, 'global']) {
    const roles = await redisRbacRepository.getRoles(svc)
    if (!roles) continue
    for (const perms of Object.values(roles)) {
      for (const p of perms) {
        if (p === '*') return '*'
        set.add(p)
      }
    }
  }
  return set
}
