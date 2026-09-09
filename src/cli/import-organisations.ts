/**
 * Import organisations from a directory that already holds them.
 *
 * Reads a plain document rather than any particular system: whatever produced it knows about the
 * source, and this service knows about organisations. That boundary is why the same command works
 * for a deployment whose directory this code has never heard of.
 *
 * Reports what it would change and exits without writing, unless told to apply. Applying is one
 * transaction and is replayable — every write is keyed on the identifier the source already had,
 * so running it twice changes nothing and running it again after a failure completes it.
 *
 * Nothing is ever deleted. An organisation missing from the input is left alone: an input can be
 * incomplete for reasons that have nothing to do with intent, and absence must not read as revoke.
 *
 * Usage:
 *   node dist/cli/import-organisations.js <file.json> [--apply]
 *
 * Exit codes:
 *   0 — reported, or applied
 *   1 — the file could not be read, or does not describe organisations
 *   2 — the input would merge or contradict something, and was refused
 *   3 — the store refused the write
 */

import { readFile } from 'node:fs/promises'
import { z } from 'zod'
import {
  applyOrganisations,
  closeOrganisationStore,
  organisationStoreConfigured,
  organisationsById,
  OrganisationStoreUnavailableError,
  type OrganisationRecord,
} from '../services/organisation-store.js'

const EXIT = { SUCCESS: 0, UNREADABLE: 1, REFUSED: 2, STORE: 3 } as const

/**
 * Strict on purpose: an unknown key is far more likely to be a field somebody meant to be imported
 * than a harmless extra, and silently dropping it is how an entitlement goes missing.
 */
const Record_ = z
  .object({
    id: z.string().uuid('an organisation id must be a UUID, so it can be the one the source had'),
    name: z.string().min(1),
    tenant: z.string().min(1),
    attributes: z.record(z.unknown()).optional(),
    deployments: z
      .array(z.object({ application: z.string().min(1), enabled: z.boolean() }).strict())
      .optional(),
    members: z
      .array(z.object({ subjectId: z.string().min(1), role: z.string().min(1) }).strict())
      .optional(),
  })
  .strict()

const Document_ = z.object({ organisations: z.array(Record_).min(1) }).strict()

/** What the input would do to something already held, refused before anything is written. */
function contradictions(records: readonly OrganisationRecord[]): string[] {
  const problems: string[] = []

  const seen = new Map<string, OrganisationRecord>()
  for (const record of records) {
    const previous = seen.get(record.id)
    if (previous) {
      // Two rows for one identifier cannot both be applied, and picking one is a guess about which
      // organisation somebody meant.
      problems.push(
        `${record.id} appears twice, as "${previous.name}" and "${record.name}" — one input, two organisations`,
      )
    }
    seen.set(record.id, record)
  }

  for (const record of records) {
    if (record.members?.some((member) => member.subjectId.includes('@'))) {
      // An address is a trait its owner can change. Keyed on one, an entitlement moves with it and
      // a reused address inherits the last holder's.
      problems.push(`${record.id} has a member keyed on an address rather than a subject`)
    }
  }

  return problems
}

async function main(): Promise<number> {
  const [path, ...flags] = process.argv.slice(2)
  const apply = flags.includes('--apply')

  if (!path) {
    console.error('usage: import-organisations <file.json> [--apply]')
    return EXIT.UNREADABLE
  }

  if (!organisationStoreConfigured()) {
    console.error('ORGANISATION_DATABASE_URL is not set: there is nowhere to import into.')
    return EXIT.UNREADABLE
  }

  let document: z.infer<typeof Document_>
  try {
    document = Document_.parse(JSON.parse(await readFile(path, 'utf8')))
  } catch (failure) {
    console.error(`${path} does not describe organisations: ${String(failure)}`)
    return EXIT.UNREADABLE
  }

  const records = document.organisations
  const refusals = contradictions(records)
  if (refusals.length > 0) {
    console.error('Refused, nothing written:')
    for (const refusal of refusals) console.error(`  ${refusal}`)
    return EXIT.REFUSED
  }

  // Read first, so the report says what CHANGES rather than what the file contains. An import that
  // reports its own input tells you nothing about the state you are about to be in.
  const held = new Map((await organisationsById(records.map((r) => r.id))).map((o) => [o.id, o]))

  for (const record of records) {
    const existing = held.get(record.id)
    const change = !existing
      ? 'new'
      : existing.name !== record.name || existing.tenant !== record.tenant
        ? `updated (was "${existing.name}" in ${existing.tenant})`
        : 'unchanged'
    console.log(
      `  ${record.id}  ${record.tenant.padEnd(14)} ${record.name.padEnd(24)} ` +
        `${String(record.deployments?.length ?? 0).padStart(2)} app(s) ` +
        `${String(record.members?.length ?? 0).padStart(3)} member(s)  ${change}`,
    )
  }

  const tenants = new Set(records.map((r) => r.tenant))
  console.log(
    `\n  ${records.length} organisation(s) across ${tenants.size} namespace(s); ` +
      `${records.length - held.size} not held yet`,
  )

  if (!apply) {
    console.log('\n  Nothing written. Pass --apply to write it.')
    return EXIT.SUCCESS
  }

  try {
    const outcome = await applyOrganisations(records)
    console.log(
      `\n  Applied: ${outcome.organisations} organisation(s), ` +
        `${outcome.deployments} deployment(s), ${outcome.members} membership(s).`,
    )
    return EXIT.SUCCESS
  } catch (failure) {
    console.error(
      failure instanceof OrganisationStoreUnavailableError
        ? `\n  Nothing was written: ${failure.message}`
        : `\n  Nothing was written: ${String(failure)}`,
    )
    return EXIT.STORE
  }
}

main()
  .then(async (code) => {
    await closeOrganisationStore()
    process.exit(code)
  })
  .catch(async (failure: unknown) => {
    console.error(String(failure))
    await closeOrganisationStore()
    process.exit(EXIT.STORE)
  })
