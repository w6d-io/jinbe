/** A structural check of a value against a CRD's openAPIV3Schema: what the API server would refuse or prune. */

export type Schema = {
  type?: string
  properties?: Record<string, Schema>
  additionalProperties?: Schema | boolean
  items?: Schema
  required?: string[]
  enum?: unknown[]
  pattern?: string
  minLength?: number
  maxLength?: number
  minimum?: number
  maximum?: number
  minItems?: number
  maxItems?: number
  'x-kubernetes-preserve-unknown-fields'?: boolean
}

/** Every way `value` breaks `schema`, as `path: problem`. */
export function violations(schema: Schema, value: unknown, path: string): string[] {
  const out: string[] = []
  const kind = Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value
  const expected = schema.type === 'integer' ? 'number' : schema.type
  if (expected && kind !== expected) return [`${path}: ${kind} where the schema wants ${schema.type}`]
  if (schema.type === 'integer' && !Number.isInteger(value)) out.push(`${path}: not an integer`)
  if (schema.enum && !schema.enum.includes(value)) out.push(`${path}: ${JSON.stringify(value)} not in ${JSON.stringify(schema.enum)}`)
  if (typeof value === 'string') {
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) out.push(`${path}: ${JSON.stringify(value)} does not match ${schema.pattern}`)
    if (schema.minLength !== undefined && value.length < schema.minLength) out.push(`${path}: shorter than ${schema.minLength}`)
    if (schema.maxLength !== undefined && value.length > schema.maxLength) out.push(`${path}: longer than ${schema.maxLength}`)
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) out.push(`${path}: below ${schema.minimum}`)
    if (schema.maximum !== undefined && value > schema.maximum) out.push(`${path}: above ${schema.maximum}`)
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) out.push(`${path}: fewer than ${schema.minItems} items`)
    if (schema.maxItems !== undefined && value.length > schema.maxItems) out.push(`${path}: more than ${schema.maxItems} items`)
    if (schema.items) value.forEach((v, i) => out.push(...violations(schema.items!, v, `${path}[${i}]`)))
  }
  if (kind === 'object') {
    const obj = value as Record<string, unknown>
    for (const key of schema.required ?? []) if (!(key in obj)) out.push(`${path}.${key}: required`)
    for (const [key, v] of Object.entries(obj)) {
      if (v === undefined) continue
      const sub = schema.properties?.[key]
      if (sub) out.push(...violations(sub, v, `${path}.${key}`))
      else if (typeof schema.additionalProperties === 'object') out.push(...violations(schema.additionalProperties, v, `${path}.${key}`))
      else if (!schema['x-kubernetes-preserve-unknown-fields'] && schema.additionalProperties !== true) out.push(`${path}.${key}: not in the CRD schema (the API server would prune it)`)
    }
  }
  return out
}
