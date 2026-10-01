import { redisRbacRepository, type GroupDefinition } from './redis-rbac.repository.js'

type RolesOf = (service: string) => Record<string, string[]> | null | undefined

/**
 * A group's binding names, per app, roles OF THAT APP — the policy reads each role in its app's roles
 * only, so a name the app does not define grants nothing and is a mistake. Refused (422) wherever a
 * binding is written: group create, edit, bundle import.
 */
export class InvalidBindingError extends Error {
  statusCode = 422
  constructor(public problems: string[]) {
    super(`Invalid group binding: ${problems.join('; ')}`)
  }
}

/** What is wrong with this binding, read against each service's roles; empty when nothing. */
export function bindingProblems(group: string, def: GroupDefinition, rolesOf: RolesOf): string[] {
  const problems: string[] = []
  for (const [service, roles] of Object.entries(def)) {
    const defined = rolesOf(service)
    if (!defined) {
      if (roles.length > 0) problems.push(`${group}: ${service} has no roles`)
      continue
    }
    const unknown = roles.filter((r) => !Object.prototype.hasOwnProperty.call(defined, r))
    if (unknown.length > 0) problems.push(`${group}: ${service} defines no role ${unknown.join(', ')}`)
  }
  return problems
}

/** Throws InvalidBindingError when a binding names a role its service does not define (read from the store). */
export async function assertValidBinding(group: string, def: GroupDefinition): Promise<void> {
  const roles = new Map<string, Record<string, string[]> | null>()
  for (const service of Object.keys(def)) roles.set(service, await redisRbacRepository.getRoles(service))
  const problems = bindingProblems(group, def, (s) => roles.get(s))
  if (problems.length > 0) throw new InvalidBindingError(problems)
}
