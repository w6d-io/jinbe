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
    'The group\'s "Members must use 2FA" switch. required: members need two-step sign-in (aal2) on every permission-carrying ' +
    'route, and nobody is added before enrolling a second factor (enrolBeforeJoining, always equal). source: group_setting ' +
    '(stored) | default (not stored yet: on for a group that can write or holds *). defaultRequired: what the default would be.',
  properties: {
    required: { type: 'boolean' },
    source: { type: 'string', enum: ['group_setting', 'default'] },
    enrolBeforeJoining: { type: 'boolean' },
    defaultRequired: { type: 'boolean' },
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
      description: 'The groups switched to "Members must use 2FA"; explicit false = some group still runs on its default (not pinned yet).',
      properties: { groups: stringList, explicit: { type: 'boolean' } },
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
