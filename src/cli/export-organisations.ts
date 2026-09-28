/**
 * Write every organisation this service holds — records, deployments, members — and everybody's
 * groups, as the document import-organisations reads.
 *
 * From whichever store the deployment runs (ORGANISATION_STORE), so it is both the backup of the
 * kratos store's registry and the first half of moving from postgres to kratos:
 *
 *   ORGANISATION_STORE=postgres node dist/cli/export-organisations.js > organisations.json
 *   ORGANISATION_STORE=kratos   node dist/cli/import-organisations.js organisations.json          # report
 *   ORGANISATION_STORE=kratos   node dist/cli/import-organisations.js organisations.json --apply  # write
 *
 * The document goes to stdout, the summary to stderr. Reads only; nothing is changed.
 *
 * Exit codes:
 *   0 — written
 *   3 — the store could not be read (nothing is printed on stdout: a partial export is worse than none)
 */

import { pathToFileURL } from 'node:url'
import {
  allGroupMemberships,
  allOrganisations,
  closeOrganisationStore,
  deploymentsOf,
  membersOf,
  organisationStoreConfigured,
  organisationStoreMode,
  type OrganisationRecord,
} from '../services/organisation-store.js'

export interface ExportDocument {
  organisations: OrganisationRecord[]
  groups: Array<{ subjectId: string; groups: string[] }>
}

export async function exportOrganisations(): Promise<ExportDocument> {
  const organisations: OrganisationRecord[] = []
  for (const o of await allOrganisations()) {
    const [deployments, members] = await Promise.all([deploymentsOf(o.id), membersOf(o.id)])
    organisations.push({ id: o.id, name: o.name, tenant: o.tenant, attributes: o.attributes, deployments, members })
  }
  const groups = [...(await allGroupMemberships()).entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([subjectId, held]) => ({ subjectId, groups: [...held].sort() }))
  return { organisations, groups }
}

async function main(): Promise<number> {
  if (!organisationStoreConfigured()) {
    console.error('ORGANISATION_STORE=postgres but ORGANISATION_DATABASE_URL is not set: there is nothing to export.')
    return 3
  }
  try {
    const document = await exportOrganisations()
    process.stdout.write(`${JSON.stringify(document, null, 2)}\n`)
    const members = document.organisations.reduce((n, o) => n + (o.members?.length ?? 0), 0)
    console.error(
      `Exported from the ${organisationStoreMode()} store: ${document.organisations.length} organisation(s), ` +
        `${members} membership(s), ${document.groups.length} group set(s).`,
    )
    return 0
  } catch (failure) {
    console.error(`Could not read the ${organisationStoreMode()} store: ${String(failure)}`)
    return 3
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
    .then(async (code) => {
      await closeOrganisationStore()
      process.exit(code)
    })
    .catch(async (failure: unknown) => {
      console.error(String(failure))
      await closeOrganisationStore()
      process.exit(3)
    })
}
