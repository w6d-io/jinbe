import type { FlatRolesMap } from '../services/redis-rbac.repository.js'
import { DEFAULT_OWNER_ROLE, signUpGroupName, type Gate, type Route, type Site } from './schemas.js'
import type { Check } from './render.js'
import { ORG_GATE } from './presets.js'

/**
 * A site's organizations (the intent's `organizations`): a way for many people to share the same
 * objects in the site's backend. On, the site's org roles (groups.orgGrantable) decide what each
 * member of an organization may do on its objects; an organization's owners hold `ownerRole` there.
 * Off (absent), the site has nothing of it: render refuses every org feature.
 *
 * Pure, like render.ts, which calls it.
 */

export const organizationsOn = (site: Pick<Site, 'organizations'>): boolean => site.organizations?.enabled === true

/** Whether an intent uses any org feature: what a stored one made before the switch existed did. */
function usesOrganizations(site: Pick<Site, 'routes' | 'groups' | 'everyOrg' | 'orgs' | 'signUp'>): boolean {
  return site.routes.items.some((r) => !!r.orgParam)
    || Object.keys(site.groups.orgGrantable).length > 0
    || Object.keys(site.everyOrg ?? {}).length > 0
    || site.orgs.length > 0
    || (!!site.signUp && site.signUp.orgs !== 'none')
}

/**
 * A STORED intent saved before the switch existed, using org features, renders with organizations
 * on (republish, drift), so nothing live loses access at the release; a new preview or save without
 * the switch is refused instead (organizationChecks). Like explicitWildcards.
 */
export function explicitOrganizations<T extends Site>(site: T): T {
  if (site.organizations || !usesOrganizations(site)) return site
  return { ...site, organizations: { enabled: true } }
}

/** The org role owners hold (`<role>` of `<site>:<role>`), when the site has organizations on and the role exists. */
export function ownerRoleOf(site: Pick<Site, 'organizations'>, orgRoles: FlatRolesMap): string | null {
  if (!organizationsOn(site)) return null
  const role = site.organizations?.ownerRole ?? DEFAULT_OWNER_ROLE
  return orgRoles[role] ? role : null
}

const OFF = 'organizations are off on this site: turn them on (organizations.enabled) to'

/** The org checks of one intent: features without the switch, the owner role, cross-tenant reach. */
export function organizationChecks(site: Site, orgRoles: FlatRolesMap, platformGroups: readonly string[]): Check[] {
  const checks: Check[] = []
  const fail = (code: string, message: string, path?: string) => checks.push({ level: 'error', code, message, path })
  if (!organizationsOn(site)) {
    site.routes.items.forEach((r, i) => {
      if (r.orgParam) fail('organizations_off', `${OFF} scope ${r.path} to an organization (orgParam)`, `routes.items.${i}.orgParam`)
    })
    if (Object.keys(site.groups.orgGrantable).length) fail('organizations_off', `${OFF} give org roles (groups.orgGrantable)`, 'groups.orgGrantable')
    if (Object.keys(site.everyOrg ?? {}).length) fail('organizations_off', `${OFF} carry roles into every organization (everyOrg)`, 'everyOrg')
    if (site.orgs.length) fail('organizations_off', `${OFF} serve organizations (orgs)`, 'orgs')
    if (site.signUp && site.signUp.orgs !== 'none') fail('organizations_off', `${OFF} put people who sign up in an organization (signUp.orgs: none)`, 'signUp.orgs')
    return checks
  }
  const explicit = site.organizations?.ownerRole
  const role = explicit ?? DEFAULT_OWNER_ROLE
  if (!orgRoles[role]) {
    const message = `owners hold org role '${role}', which this site does not have: add ${site.name}-${role} under groups.orgGrantable`
    if (explicit) fail('unknown_owner_role', message, 'organizations.ownerRole')
    else checks.push({ level: 'warn', code: 'no_owner_role', message: `${message}, or name another (organizations.ownerRole); until then owners hold nothing here`, path: 'organizations' })
  }
  // A site's own groups (<site>-…, the sign-up group) are filled from the site itself, by its builders
  // and its sign-up: an everyOrg role bound there would reach into every organization the site serves.
  const own = platformGroups.filter((g) => g.startsWith(`${site.name}-`) || g === signUpGroupName(site.name))
  for (const role of Object.keys(site.everyOrg ?? {})) {
    const bound = own.filter((g) => (g === signUpGroupName(site.name) ? site.signUp?.roles ?? [] : site.groups.platform[g] ?? []).includes(role))
    if (bound.length) fail('every_org_own_group', `everyOrg '${role}' is bound by the site's own group ${bound.join(', ')}: its members would act in every organization the site serves`, `everyOrg.${role}`)
  }
  return checks
}

/** A gate that admits OAuth2 tokens (an org API key among them). */
export const admitsTokens = (gate: Pick<Gate, 'authenticators'>): boolean => gate.authenticators.some((a) => a.handler === 'oauth2_introspection')

/**
 * A gate admitting OAuth2 tokens whose authorizer is not the policy lets any organization's key in:
 * only the policy checks that the key's organization is served by the site (rbac.rego client clause).
 */
export function tokenGateChecks(site: Pick<Site, 'gates'>): Check[] {
  return site.gates.flatMap((g, i): Check[] => (admitsTokens(g) && g.authorizer !== 'policy' && g.authorizer.handler !== 'deny'
    ? [{ level: 'error', code: 'tokens_need_policy', message: `gate '${g.id}' admits API tokens but lets them pass without the policy: any organization's key would get in. Let the policy decide (Who may pass: policy)`, path: `gates.${i}.authorizer` }]
    : []))
}

/** The org-scoped template route's path under a site's prefix: everything under /orgs/:orgId/. */
export const orgTemplatePath = (prefix?: string): string => `${prefix ?? ''}/orgs/:orgId/:any*`

/**
 * What a template adds to a site to turn organizations on (kuma and the MCP use it as is): the switch
 * (owners hold `admin`), the organization gate (presets.ts ORG_GATE), one org-scoped route
 * `/orgs/:orgId/:any*` on it asking `<site>:use`, and the default org roles `<site>-admin` (site role
 * admin) and `<site>-member` (site role user, of the standard set). A developer then puts the
 * service's routes under /orgs/:orgId/…, and the gateway lets a person through only with a role in
 * that org, and a key only for its own org.
 */
export function organizationTemplate(site: Pick<Site, 'name'> & { address: Pick<Site['address'], 'pathPrefix'> }): {
  organizations: NonNullable<Site['organizations']>
  gate: Gate
  route: Route
  orgGrantable: Site['groups']['orgGrantable']
} {
  return {
    organizations: { enabled: true, ownerRole: DEFAULT_OWNER_ROLE },
    gate: structuredClone(ORG_GATE),
    route: {
      id: 'org',
      methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'],
      path: orgTemplatePath(site.address.pathPrefix),
      gate: ORG_GATE.id,
      access: { kind: 'permission', permission: `${site.name}:use` },
      orgParam: 'orgId',
      source: 'template',
    },
    orgGrantable: {
      [`${site.name}-admin`]: { label: 'Admins', roles: ['admin'] },
      [`${site.name}-member`]: { label: 'Members', roles: ['user'] },
    },
  }
}
