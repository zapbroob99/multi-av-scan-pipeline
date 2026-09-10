import { readFile, writeFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'
import openapiTS, { astToString } from 'openapi-typescript'

const snapshot = new URL('../../contracts/browser.openapi.json', import.meta.url)
const output = new URL('../../src/lib/api.generated.ts', import.meta.url)
// Accept only local, self-contained schemas. Generation must never resolve a
// deployment URL, read credentials, or depend on a running MASP instance.
function checkRefs(value) {
  if (!value || typeof value !== 'object') return
  if ('$ref' in value && (typeof value.$ref !== 'string' || !value.$ref.startsWith('#/'))) throw new Error('External schema references are not allowed.')
  for (const child of Object.values(value)) checkRefs(child)
}
export async function render(schema) {
  checkRefs(schema)
  return '// Generated from contracts/browser.openapi.json. Do not edit.\n'
    + astToString(await openapiTS(schema, { alphabetize: true, defaultNonNullable: false }))
}

export async function sync({ source = snapshot, target = output, check = false } = {}) {
  const generated = await render(JSON.parse(await readFile(source, 'utf8')))
  if (check) {
    const actual = await readFile(target, 'utf8').catch(error => { if (error.code === 'ENOENT') return ''; throw error })
    return actual.replaceAll('\r\n', '\n') === generated
  }
  await writeFile(target, generated)
  return true
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!await sync({ check: process.argv.includes('--check') })) {
    console.error('Browser TypeScript contracts are stale. Run npm --prefix frontend run contracts:generate.')
    process.exitCode = 1
  } else console.log('Browser TypeScript contracts are up to date.')
}
