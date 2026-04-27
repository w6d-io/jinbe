import type { OathkeeperRule } from '../../../schemas/rbac/access-rules.schema.js'

/**
 * Creates a standard Oathkeeper rule for a service
 */
export function createOathkeeperRule(
  id: string,
  overrides: Partial<OathkeeperRule> = {}
): OathkeeperRule {
  return {
    id,
    upstream: {
      url: `http://${id}.w6d-ops:8080`,
    },
    match: {
      url: `https://kuma.dev.w6d.io/api/${id}/<**>`,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    },
    authenticators: [{ handler: 'cookie_session' }],
    authorizer: { handler: 'remote_json' },
    mutators: [{ handler: 'header' }],
    ...overrides,
  }
}

/**
 * Creates a health check Oathkeeper rule (public, no auth)
 */
export function createHealthRule(serviceName: string): OathkeeperRule {
  return {
    id: `${serviceName}-health`,
    upstream: {
      url: `http://${serviceName}.w6d-ops:8080/health`,
    },
    match: {
      url: `https://kuma.dev.w6d.io/api/${serviceName}/health`,
      methods: ['GET', 'OPTIONS'],
    },
    authenticators: [{ handler: 'noop' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  }
}

/**
 * Creates a sample access rules array
 */
export function createAccessRulesFixture(): OathkeeperRule[] {
  return [
    createOathkeeperRule('jinbe'),
    createHealthRule('jinbe'),
    createOathkeeperRule('kuma'),
    createHealthRule('kuma'),
  ]
}

/**
 * Creates an empty access rules array
 */
export function createEmptyAccessRulesFixture(): OathkeeperRule[] {
  return []
}

/**
 * Creates an access rule with JWT authentication
 */
export function createJwtAuthRule(id: string): OathkeeperRule {
  return {
    id,
    upstream: {
      url: `http://${id}.w6d-ops:8080`,
    },
    match: {
      url: `https://kuma.dev.w6d.io/api/${id}/<**>`,
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
    },
    authenticators: [
      {
        handler: 'jwt',
        config: {
          jwks_urls: ['https://auth.example.com/.well-known/jwks.json'],
        },
      },
    ],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'header' }],
  }
}
