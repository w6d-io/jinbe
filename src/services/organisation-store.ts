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
 *
 * `group_members` holds the one fact that grows with the company: which groups a person is in. What
 * a group GIVES — roles, per organisation — is deliberately not here: it changes at a release, it
 * must be reviewed, and a diff of it is the only way anybody can see a permission change coming. So
 * it lives in the repository, and this table stays one row per person per group, whatever the number
 * of organisations.
 *
 * Keyed on the subject, never the address: an address is a trait its owner can change, and a changed
 * one must not move an entitlement — nor a reused one inherit the last holder's.
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

CREATE TABLE IF NOT EXISTS group_members (
  subject_id  text NOT NULL,
  group_name  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  created_by  text,
  PRIMARY KEY (subject_id, group_name)
);
CREATE INDEX IF NOT EXISTS group_members_group_idx ON group_members (group_name);
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

/**
 * What each of these subjects belongs to, in one query.
 *
 * A listing asks about everybody on the page, and asking per row turns one screen into as many
 * round trips as it has rows — which is how a list becomes slow enough that somebody caches it and
 * then shows a stale one.
 */
export async function membershipsForSubjects(
  subjectIds: readonly string[],
): Promise<Map<string, string[]>> {
  const held = new Map<string, string[]>()
  if (subjectIds.length === 0) return held

  const rows = await query<{ subject_id: string; organisation_id: string }>(
    `SELECT DISTINCT subject_id, organisation_id
     FROM organisation_members
     WHERE subject_id = ANY($1::text[])`,
    [subjectIds],
  )

  for (const row of rows) {
    const already = held.get(row.subject_id)
    if (already) already.push(row.organisation_id)
    else held.set(row.subject_id, [row.organisation_id])
  }
  return held
}

/**
 * Which groups a person is in.
 *
 * The whole page in one query, for the same reason as the memberships above: asking per row is how
 * a list becomes slow enough that somebody caches it and then shows a stale one.
 *
 * A subject with no group is ABSENT from the map rather than present with an empty list — the caller
 * decides what "belongs to no group" should look like on its screen, and defaulting here would make
 * "has none" and "was not asked about" the same answer.
 */
export async function groupsForSubjects(
  subjectIds: readonly string[],
): Promise<Map<string, string[]>> {
  const held = new Map<string, string[]>()
  if (subjectIds.length === 0) return held

  const rows = await query<{ subject_id: string; group_name: string }>(
    `SELECT subject_id, group_name
     FROM group_members
     WHERE subject_id = ANY($1::text[])
     ORDER BY group_name`,
    [subjectIds],
  )

  for (const row of rows) {
    const already = held.get(row.subject_id)
    if (already) already.push(row.group_name)
    else held.set(row.subject_id, [row.group_name])
  }
  return held
}

/**
 * Everybody's groups, for building the artefact the authorization engine decides against.
 *
 * One query and no paging: this is the fact that grows with the company, and it is exactly the thing
 * that must be read whole — a partial answer here would silently remove somebody's access rather
 * than fail.
 */
export async function allGroupMemberships(): Promise<Map<string, string[]>> {
  const held = new Map<string, string[]>()
  const rows = await query<{ subject_id: string; group_name: string }>(
    'SELECT subject_id, group_name FROM group_members ORDER BY subject_id, group_name',
    [],
  )
  for (const row of rows) {
    const already = held.get(row.subject_id)
    if (already) already.push(row.group_name)
    else held.set(row.subject_id, [row.group_name])
  }
  return held
}

/** Who is in one group, for the screen that administers it. */
export async function membersOfGroup(groupName: string): Promise<string[]> {
  const rows = await query<{ subject_id: string }>(
    'SELECT subject_id FROM group_members WHERE group_name = $1 ORDER BY subject_id',
    [groupName],
  )
  return rows.map((row) => row.subject_id)
}

/**
 * Put somebody in a group.
 *
 * Idempotent: assigning twice is not an error, so a repair can be re-run and a double click cannot
 * fail. `created_by` is recorded because "who granted this" is the first question asked when
 * somebody turns out to hold more than expected.
 */
export async function addToGroup(
  subjectId: string,
  groupName: string,
  createdBy?: string,
): Promise<void> {
  await query(
    `INSERT INTO group_members (subject_id, group_name, created_by)
     VALUES ($1, $2, $3)
     ON CONFLICT (subject_id, group_name) DO NOTHING`,
    [subjectId, groupName, createdBy ?? null],
  )
}

/**
 * Apply a whole group change at once, or none of it.
 *
 * The revocations and the grants of one change belong together: applied one statement at a time, a
 * failure halfway leaves a person holding some of what was asked for and some of what was not — a
 * state nobody requested and nothing records. The gates upstream decide the change as a whole, so
 * the store commits it as a whole.
 *
 * The ORDER inside the transaction still matters for a reader of the audit trail, and it is the same
 * one the caller relies on: what is taken away goes first.
 */
export async function applyGroupChange(
  subjectId: string,
  revoked: readonly string[],
  granted: readonly string[],
  createdBy?: string,
): Promise<void> {
  if (revoked.length === 0 && granted.length === 0) return
  await ready()
  const client = await connection()
    .connect()
    .catch((failure: unknown) => {
      throw new OrganisationStoreUnavailableError(`Could not open a transaction: ${String(failure)}`)
    })

  try {
    await client.query('BEGIN')
    for (const groupName of revoked) {
      await client.query('DELETE FROM group_members WHERE subject_id = $1 AND group_name = $2', [
        subjectId,
        groupName,
      ])
    }
    for (const groupName of granted) {
      await client.query(
        `INSERT INTO group_members (subject_id, group_name, created_by)
         VALUES ($1, $2, $3)
         ON CONFLICT (subject_id, group_name) DO NOTHING`,
        [subjectId, groupName, createdBy ?? null],
      )
    }
    await client.query('COMMIT')
  } catch (failure) {
    await client.query('ROLLBACK').catch(() => undefined)
    throw new OrganisationStoreUnavailableError(`The groups were not changed: ${String(failure)}`)
  } finally {
    client.release()
  }
}

/** Take somebody out of a group. Removing what is not there is not an error either. */
export async function removeFromGroup(subjectId: string, groupName: string): Promise<void> {
  await query('DELETE FROM group_members WHERE subject_id = $1 AND group_name = $2', [
    subjectId,
    groupName,
  ])
}

/**
 * Clear every group of a subject that no longer exists.
 *
 * A row left behind names a subject nobody can look up, and would grant to whoever is issued that
 * identifier next.
 */
export async function forgetGroupsOf(subjectId: string): Promise<void> {
  await query('DELETE FROM group_members WHERE subject_id = $1', [subjectId])
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
 * Which applications every organisation is entitled to, for the engine.
 *
 * The second dimension of the model, and a COMMERCIAL fact rather than a personal one: what a role
 * gives says what somebody may do, this says which applications their organisation has at all. The
 * two are kept apart because they change for different reasons — one when somebody is promoted, the
 * other when a contract or a deployment changes.
 *
 * Only what is ON. A row with `enabled = false` is a deployment somebody turned off, and reading it
 * as an entitlement would let a subscription that has lapsed keep deciding.
 */
export async function allEntitlements(): Promise<Map<string, string[]>> {
  const held = new Map<string, string[]>()
  const rows = await query<{ organisation_id: string; application: string }>(
    'SELECT organisation_id, application FROM organisation_deployments WHERE enabled = true ORDER BY organisation_id, application',
    [],
  )
  for (const row of rows) {
    const already = held.get(row.organisation_id)
    if (already) already.push(row.application)
    else held.set(row.organisation_id, [row.application])
  }
  return held
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
