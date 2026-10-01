/**
 * Regenerate policy-contract.json — jinbe's authz v2 model and who must reach each route row — for
 * opal-policies CI (authz-v2/contract.ts). Pure: no server, nothing external. CI fails when stale.
 */
import { writeFile } from 'fs/promises'
import { renderPolicyContract } from '../authz-v2/contract.js'

await writeFile(new URL('../../policy-contract.json', import.meta.url), renderPolicyContract(), 'utf8')
// eslint-disable-next-line no-console
console.log('policy-contract.json regenerated')
