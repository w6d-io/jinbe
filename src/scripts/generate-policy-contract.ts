/**
 * Regenerate policy-contract.json — jinbe's authorization model and who must reach each route row — for
 * opal-policies CI (policy/contract.ts). Pure: no server, nothing external. CI fails when stale.
 */
import { writeFile } from 'fs/promises'
import { renderPolicyContract } from '../policy/contract.js'

await writeFile(new URL('../../policy-contract.json', import.meta.url), renderPolicyContract(), 'utf8')
// eslint-disable-next-line no-console
console.log('policy-contract.json regenerated')
