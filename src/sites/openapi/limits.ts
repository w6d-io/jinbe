/**
 * The bounds of an OpenAPI import (docs: research/openapi-import.md §1). The spec is written by the
 * upstream team, i.e. untrusted: every size, depth and count is capped before it can cost anything.
 */

export const LIMITS = {
  /** Raw spec, in UTF-8 bytes. */
  bytes: 5 * 1024 * 1024,
  /** YAML alias expansions (billion laughs). `<<` merge keys are not honoured at all. */
  yamlAliases: 50,
  depth: 64,
  nodes: 200_000,
  /** Characters in any one string or key. */
  string: 64 * 1024,
  paths: 2000,
  operations: 2000,
  pathLength: 512,
  segments: 32,
  params: 16,
  operationId: 128,
  refHops: 16,
  /** Wall clock of one parse, once the worker is up. */
  parseMs: 2000,
  /** The worker's own start (module loading), before the parse clock runs. */
  bootMs: 10_000,
  heapMb: 96,
} as const

/** Keys no legitimate spec has; refused rather than sanitised (prototype pollution). */
export const FORBIDDEN_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype'])

/** A spec refused, with a stable code for the UI. Always a 422: the input is the problem. */
export class SpecError extends Error {
  readonly statusCode = 422
  constructor(readonly code: string, message: string) {
    super(message)
  }
}

export const specError = (code: string, message: string) => new SpecError(code, message)
