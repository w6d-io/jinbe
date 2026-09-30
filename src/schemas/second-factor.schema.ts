/**
 * Response schemas for the second-factor requirements (second-factor/requirements.ts): one person's
 * picture, a site's bar, and the map the console and the MCP draw badges from.
 */

const stringList = { type: 'array', items: { type: 'string' } }

export const userSecondFactorJsonSchema = {
  type: 'object',
  nullable: true,
  description:
    'required/requiredBecause: the groups that make two-step sign-in (aal2) mandatory; enrolled/methods: null when unread; ' +
    'currentAal, factorAgeMin, stepUpFresh: the caller\'s own session (null when describing somebody else); ' +
    'stepUpPermissions: their permissions that need a second factor proven within 15 minutes (null when unread).',
  properties: {
    required: { type: 'boolean' },
    requiredBecause: stringList,
    enrolled: { type: 'boolean', nullable: true },
    methods: { type: 'array', nullable: true, items: { type: 'string' } },
    currentAal: { type: 'string', nullable: true },
    factorAgeMin: { type: 'integer', nullable: true },
    stepUpFresh: { type: 'boolean', nullable: true },
    stepUpPermissions: { type: 'array', nullable: true, items: { type: 'string' } },
  },
}

export const siteSecondFactorJsonSchema = {
  type: 'object',
  description: "A site's own two-step sign-in bar (login.twoFactor), with a sentence for a person.",
  properties: {
    scope: { type: 'string', enum: ['none', 'writes', 'all', 'routes'] },
    routes: stringList,
    clients: { type: 'string', nullable: true, enum: ['exempt', 'refused', null] },
    minAal: { type: 'string', enum: ['aal1', 'aal2'] },
    summary: { type: 'string' },
  },
}

export const groupSecondFactorJsonSchema = {
  type: 'object',
  description:
    'required: members need two-step sign-in (aal2) on every permission-carrying route; source: setting | default ' +
    '(super_admins, no setting saved) | null; enrolBeforeJoining: confers a global role, so whoever is added must have enrolled a second factor.',
  properties: {
    required: { type: 'boolean' },
    source: { type: 'string', nullable: true, enum: ['setting', 'default', null] },
    enrolBeforeJoining: { type: 'boolean' },
  },
}

export const stepUpRuleJsonSchema = {
  type: 'object',
  description:
    'required: a second factor proven within maxAgeMin minutes; viaPersonalKey: a personal key may stand in with the factor ' +
    'proven at its creation, up to maxAgeDays (null: it may not); fourEyes: a second person in prod.',
  properties: {
    required: { type: 'boolean' },
    maxAgeMin: { type: 'integer', nullable: true },
    viaPersonalKey: { type: 'object', nullable: true, properties: { maxAgeDays: { type: 'integer' } } },
    fourEyes: { type: ['string', 'boolean'] },
  },
}

export const secondFactorMapJsonSchema = {
  type: 'object',
  properties: {
    rules: {
      type: 'array',
      items: {
        type: 'object',
        properties: { id: { type: 'string' }, label: { type: 'string' }, status: { type: 'string', enum: ['enforced', 'planned'] } },
      },
    },
    limits: {
      type: 'object',
      properties: {
        stepUpMaxAgeMin: { type: 'integer' },
        personalKeyMaxAgeDays: { type: 'integer' },
        oauthGrantMaxAgeHours: { type: 'integer' },
      },
    },
    signIn: {
      type: 'object',
      nullable: true,
      description: 'The groups whose members must use two-step sign-in; explicit false = the default applies (no setting saved).',
      properties: { groups: stringList, explicit: { type: 'boolean' }, defaultGroups: stringList },
    },
    groups: {
      type: 'array',
      nullable: true,
      description: 'Null without groups:read, or when the groups cannot be read (see unavailable).',
      items: { type: 'object', properties: { name: { type: 'string' }, secondFactor: groupSecondFactorJsonSchema } },
    },
    permissions: {
      type: 'array',
      items: { type: 'object', properties: { name: { type: 'string' }, label: { type: 'string' }, stepUpRule: stepUpRuleJsonSchema } },
    },
    roles: {
      type: 'array',
      items: { type: 'object', properties: { name: { type: 'string' }, group: { type: 'string' }, stepUpPermissions: stringList } },
    },
    sites: {
      type: 'array',
      nullable: true,
      description: 'The applied version of each site (what visitors meet); null without sites:read or when unreadable.',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          displayName: { type: 'string' },
          host: { type: 'string' },
          applied: { type: 'boolean' },
          secondFactor: siteSecondFactorJsonSchema,
        },
      },
    },
    organizations: {
      type: 'object',
      properties: { rules: stringList, note: { type: 'string' } },
    },
    unavailable: { ...stringList, description: 'Sections that could not be read (signIn, groups, sites).' },
  },
}
