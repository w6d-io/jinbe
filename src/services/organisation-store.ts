import { Pool } from 'pg'
import { env } from '../config/index.js'

/**
 * Organisations as records this service owns, rather than a set inferred from group names.
 *
 * The inferred model cannot hold what a directory knows about an organisation — a label somebody
 * can read, which namespace it deploys into, which applications it runs, what tier it is on — and
 * it cannot answer about a subject the caller is not. Both are needed the moment this service is
 * the place other services ask.
 *
 * Deliberately relational and deliberately not the document store this service uses for the
 * platform it manages: these rows are structure, they are joined and constrained, and losing one
 * silently is not recoverable from a cache.
 *
 * Whatever else a directory carries — a tier, a contract, a commercial range — travels in
 * `attributes` rather than in columns named after one deployment's vocabulary. Anything that
 * decides an entitlement MUST be carried here, because an organisation imported without it grants
 * differently than the one it was copied from, and nothing says so.
 */
export class OrganisationStoreUnavailableError extends Error {}

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

/**
 * The schema, applied on first use and safe to apply again.
 *
 * `tenant` carries no unique constraint on purpose: a namespace is measured to host more than one
 * organisation, and a constraint that assumed otherwise would merge two of them into one on import
 * — silently, and with the memberships of both.
 */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS organisations (
  id          uuid PRIMARY KEY,
  name        text NOT NULL,
  tenant      text NOT NULL,
  attributes  jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS organisations_tenant_idx ON organisations (tenant);

CREATE TABLE IF NOT EXISTS organisation_deployments (
  organisation_id uuid NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
  application     text NOT NULL,
  enabled         boolean NOT NULL,
  PRIMARY KEY (organisation_id, application)
);

CREATE TABLE IF NOT EXISTS organisation_members (
  organisation_id uuid NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
  subject_id      text NOT NULL,
  role            text NOT NULL,
  PRIMARY KEY (organisation_id, subject_id, role)
);
CREATE INDEX IF NOT EXISTS organisation_members_subject_idx ON organisation_members (subject_id);
`

let pool: Pool | null = null
let schemaReady: Promise<void> | null = null

/** Whether this deployment has somewhere to keep organisations. */
export function organisationStoreConfigured(): boolean {
  return Boolean(env.ORGANISATION_DATABASE_URL)
}

function connection(): Pool {
  if (!env.ORGANISATION_DATABASE_URL) {
    throw new OrganisationStoreUnavailableError('No organisation database is configured.')
  }
  pool ??= new Pool({
    connectionString: env.ORGANISATION_DATABASE_URL,
    max: env.ORGANISATION_DATABASE_POOL_MAX,
    // A request waiting on a connection for ever is a request nobody times out. Refusing is worse
    // for one caller and better for the service, and it is visible.
    connectionTimeoutMillis: env.ORGANISATION_DATABASE_TIMEOUT_MS,
    // Named authority: the certificate is still checked, against the one the deployment says signed
    // it. Disabling the check instead would encrypt the connection to whatever answered, which is
    // the shape of protection that reads as protection and is not.
    ...(env.ORGANISATION_DATABASE_CA
      ? { ssl: { ca: env.ORGANISATION_DATABASE_CA, rejectUnauthorized: true } }
      : {}),
  })
  return pool
}

/** Applied once per process, and awaited by every read so none can run against a missing table. */
async function ready(): Promise<void> {
  schemaReady ??= connection()
    .query(SCHEMA)
    .then(() => undefined)
    .catch((failure: unknown) => {
      // Cleared so the next caller tries again: a database that was starting up must not leave the
      // process convinced for ever that its schema cannot be applied.
      schemaReady = null
      throw new OrganisationStoreUnavailableError(`Could not prepare the organisation store: ${String(failure)}`)
    })
  return schemaReady
}

async function query<T>(sql: string, values: readonly unknown[]): Promise<T[]> {
  await ready()
  try {
    const result = await connection().query(sql, values as unknown[])
    return result.rows as T[]
  } catch (failure) {
    // Never an empty answer: "cannot tell" and "belongs to nothing" are opposite facts, and one of
    // them must not be allowed to authorise anything.
    throw new OrganisationStoreUnavailableError(`The organisation store did not answer: ${String(failure)}`)
  }
}

/**
 * The organisations a subject is a member of.
 *
 * Keyed on the subject, never on an address: an address is a trait its owner can change, and a
 * changed address must not move an entitlement — nor must a reused one inherit the last holder's.
 */
export async function organisationsForSubject(subjectId: string): Promise<string[]> {
  if (!subjectId) return []
  const rows = await query<{ organisation_id: string }>(
    'SELECT DISTINCT organisation_id FROM organisation_members WHERE subject_id = $1',
    [subjectId],
  )
  return rows.map((row) => row.organisation_id)
}

/** Members of one organisation, for the screens that administer it. */
export async function membersOf(organisationId: string): Promise<OrganisationMember[]> {
  const rows = await query<{ subject_id: string; role: string }>(
    'SELECT subject_id, role FROM organisation_members WHERE organisation_id = $1 ORDER BY subject_id, role',
    [organisationId],
  )
  return rows.map((row) => ({ subjectId: row.subject_id, role: row.role }))
}

/** Every organisation, for a caller entitled to see them all. */
export async function allOrganisations(): Promise<Organisation[]> {
  const rows = await query<{ id: string; name: string; tenant: string; attributes: Record<string, unknown> }>(
    'SELECT id, name, tenant, attributes FROM organisations ORDER BY tenant, name',
    [],
  )
  return rows.map((row) => ({ id: row.id, name: row.name, tenant: row.tenant, attributes: row.attributes ?? {} }))
}

/** The named organisations, in the order asked, skipping any this store does not hold. */
export async function organisationsById(ids: readonly string[]): Promise<Organisation[]> {
  if (ids.length === 0) return []
  const rows = await query<{ id: string; name: string; tenant: string; attributes: Record<string, unknown> }>(
    'SELECT id, name, tenant, attributes FROM organisations WHERE id = ANY($1::uuid[])',
    [ids],
  )
  const held = new Map(rows.map((row) => [row.id, row]))
  return ids
    .map((id) => held.get(id))
    .filter((row): row is NonNullable<typeof row> => row !== undefined)
    .map((row) => ({ id: row.id, name: row.name, tenant: row.tenant, attributes: row.attributes ?? {} }))
}

/** Which applications an organisation runs, and whether each is on. */
export async function deploymentsOf(organisationId: string): Promise<OrganisationDeployment[]> {
  const rows = await query<{ application: string; enabled: boolean }>(
    'SELECT application, enabled FROM organisation_deployments WHERE organisation_id = $1 ORDER BY application',
    [organisationId],
  )
  return rows.map((row) => ({ application: row.application, enabled: row.enabled }))
}

/**
 * Record that somebody belongs to an organisation.
 *
 * Idempotent on the three together, so assigning a role twice is not an error and re-running a
 * repair changes nothing. The subject is the immutable identity: an address is a trait its owner can
 * change, and one that moved would take an entitlement with it.
 *
 * Refuses when the organisation is not held, rather than creating a membership pointing at nothing:
 * an edge to an organisation this service does not know is invisible everywhere it matters and
 * impossible to explain later.
 */
export async function addMember(
  organisationId: string,
  subjectId: string,
  role: string,
): Promise<void> {
  await query(
    `INSERT INTO organisation_members (organisation_id, subject_id, role)
     VALUES ($1, $2, $3)
     ON CONFLICT (organisation_id, subject_id, role) DO NOTHING`,
    [organisationId, subjectId, role],
  )
}

/**
 * Take somebody out of an organisation, or out of one role in it.
 *
 * Silent when there was nothing to remove: the caller asked for an end state, and reporting a
 * failure for an absence would make every repair look broken.
 */
export async function removeMember(
  organisationId: string,
  subjectId: string,
  role?: string,
): Promise<void> {
  if (role) {
    await query(
      'DELETE FROM organisation_members WHERE organisation_id = $1 AND subject_id = $2 AND role = $3',
      [organisationId, subjectId, role],
    )
    return
  }
  await query('DELETE FROM organisation_members WHERE organisation_id = $1 AND subject_id = $2', [
    organisationId,
    subjectId,
  ])
}

/** Every organisation somebody belongs to, so removing them everywhere takes one call. */
export async function removeMemberEverywhere(subjectId: string): Promise<void> {
  await query('DELETE FROM organisation_members WHERE subject_id = $1', [subjectId])
}

/**
 * Make somebody's memberships exactly this set.
 *
 * The screens that edit membership send an end state, not a change, so this replaces rather than
 * adds: merging would leave every removal in place for ever, which is a revoked access that still
 * works. One transaction, because a half-applied set is a membership list nobody chose.
 *
 * An empty set is a legitimate answer and removes them from everywhere. It is also what an
 * accidental empty request looks like, which is why only a caller holding the whole intended set
 * may use this — the create and delete paths add and drop one at a time instead.
 */
export async function setMemberships(
  subjectId: string,
  organisationIds: readonly string[],
  role = 'member',
): Promise<void> {
  await ready()
  const client = await connection()
    .connect()
    .catch((failure: unknown) => {
      throw new OrganisationStoreUnavailableError(`Could not open a transaction: ${String(failure)}`)
    })

  try {
    await client.query('BEGIN')
    await client.query('DELETE FROM organisation_members WHERE subject_id = $1', [subjectId])
    for (const organisationId of new Set(organisationIds)) {
      await client.query(
        `INSERT INTO organisation_members (organisation_id, subject_id, role)
         VALUES ($1, $2, $3)
         ON CONFLICT (organisation_id, subject_id, role) DO NOTHING`,
        [organisationId, subjectId, role],
      )
    }
    await client.query('COMMIT')
  } catch (failure) {
    await client.query('ROLLBACK').catch(() => undefined)
    throw new OrganisationStoreUnavailableError(`The memberships were not changed: ${String(failure)}`)
  } finally {
    client.release()
  }
}

export interface OrganisationRecord {
  readonly id: string
  readonly name: string
  readonly tenant: string
  readonly attributes?: Readonly<Record<string, unknown>>
  readonly deployments?: readonly OrganisationDeployment[]
  readonly members?: readonly OrganisationMember[]
}

export interface ApplyOutcome {
  readonly organisations: number
  readonly deployments: number
  readonly members: number
}

/**
 * Write a set of organisations, all of them or none.
 *
 * One transaction, because a half-applied import is worse than a refused one: the rows that landed
 * grant access, the rows that did not are missing, and nothing on screen distinguishes that from a
 * deliberate state.
 *
 * Replayable by construction — every write is an upsert keyed on the identifier the source already
 * had, so running it twice changes nothing and running it after a partial failure completes it.
 * Deployments and memberships of a named organisation are REPLACED rather than merged: they
 * describe a whole set, and merging would leave yesterday's removals in place for ever.
 *
 * Nothing is ever deleted here. An organisation absent from the input is left alone, because an
 * input that is incomplete for any reason — a filtered query, a source half migrated — must not
 * read as an instruction to revoke.
 */
export async function applyOrganisations(
  records: readonly OrganisationRecord[],
): Promise<ApplyOutcome> {
  await ready()
  const client = await connection()
    .connect()
    .catch((failure: unknown) => {
      throw new OrganisationStoreUnavailableError(`Could not open a transaction: ${String(failure)}`)
    })

  try {
    await client.query('BEGIN')
    let deployments = 0
    let members = 0

    for (const record of records) {
      await client.query(
        `INSERT INTO organisations (id, name, tenant, attributes, updated_at)
         VALUES ($1, $2, $3, $4::jsonb, now())
         ON CONFLICT (id) DO UPDATE
           SET name = EXCLUDED.name,
               tenant = EXCLUDED.tenant,
               attributes = EXCLUDED.attributes,
               updated_at = now()`,
        [record.id, record.name, record.tenant, JSON.stringify(record.attributes ?? {})],
      )

      if (record.deployments) {
        await client.query('DELETE FROM organisation_deployments WHERE organisation_id = $1', [record.id])
        for (const deployment of record.deployments) {
          await client.query(
            `INSERT INTO organisation_deployments (organisation_id, application, enabled)
             VALUES ($1, $2, $3)`,
            [record.id, deployment.application, deployment.enabled],
          )
          deployments += 1
        }
      }

      if (record.members) {
        await client.query('DELETE FROM organisation_members WHERE organisation_id = $1', [record.id])
        for (const member of record.members) {
          await client.query(
            `INSERT INTO organisation_members (organisation_id, subject_id, role)
             VALUES ($1, $2, $3)`,
            [record.id, member.subjectId, member.role],
          )
          members += 1
        }
      }
    }

    await client.query('COMMIT')
    return { organisations: records.length, deployments, members }
  } catch (failure) {
    await client.query('ROLLBACK').catch(() => undefined)
    throw new OrganisationStoreUnavailableError(`The import did not apply: ${String(failure)}`)
  } finally {
    client.release()
  }
}

/** Released between tests, and on shutdown. */
export async function closeOrganisationStore(): Promise<void> {
  const held = pool
  pool = null
  schemaReady = null
  await held?.end()
}
