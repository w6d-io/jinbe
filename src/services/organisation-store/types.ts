/**
 * What every organisation store answers with, whichever one the deployment runs (see ../organisation-store.ts).
 */
export class OrganisationStoreUnavailableError extends Error {}

/**
 * Not an outage: this deployment was never given a database. Kept apart so the console can say what
 * to set instead of "try again", which would never help.
 */
export class OrganisationStoreNotConfiguredError extends OrganisationStoreUnavailableError {
  constructor() {
    super(
      'No organisation database is configured: set ORGANISATION_DATABASE_URL, or ORGANISATION_STORE=kratos to keep organisations in Kratos and Redis.',
    )
  }
}

/** The 503 every organisation route answers when there is no database at all. */
export function organisationStoreNotConfigured() {
  return {
    error: 'organisation_directory_unavailable',
    reason: 'not_configured',
    message: new OrganisationStoreNotConfiguredError().message,
  } as const
}

export interface Organisation {
  readonly id: string
  readonly name: string
  readonly tenant: string
  readonly attributes: Readonly<Record<string, unknown>>
}

export interface OrganisationDeployment {
  readonly application: string
  readonly enabled: boolean
}

export interface OrganisationMember {
  readonly subjectId: string
  readonly role: string
}

export interface OrganisationRecord {
  readonly id: string
  readonly name: string
  readonly tenant: string
  readonly attributes?: Readonly<Record<string, unknown>>
  readonly deployments?: readonly OrganisationDeployment[]
  readonly members?: readonly OrganisationMember[]
}

/** What an organisation record may be changed to. Absent fields are left as they are. */
export interface OrganisationChange {
  readonly name?: string
  readonly tenant?: string
  readonly attributes?: Readonly<Record<string, unknown>>
}

/** The organisation named is not held: a 404, never an outage. */
export class OrganisationNotFoundError extends Error {
  constructor(readonly organisationId: string) {
    super(`No organisation ${organisationId} is held.`)
  }
}

/** Deleting an organisation somebody still belongs to would leave their membership pointing at nothing. */
export class OrganisationInUseError extends Error {
  constructor(readonly organisationId: string, readonly members: number) {
    super(`Organisation ${organisationId} still has ${members} member(s); remove them first.`)
  }
}

export interface ApplyOutcome {
  readonly organisations: number
  readonly deployments: number
  readonly members: number
}

