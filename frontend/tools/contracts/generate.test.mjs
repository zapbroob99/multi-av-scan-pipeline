import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { render, sync } from './generate.mjs'

const schema = { openapi: '3.1.0', info: { title: 'Fixture', version: '1' }, paths: {}, components: { schemas: {
  Example: { type: 'object', required: ['enabled'], properties: { enabled: { type: 'boolean' },
    label: { anyOf: [{ type: 'string' }, { type: 'null' }] } } },
} } }

test('generation is deterministic and preserves required, optional and nullable fields', async () => {
  const output = await render(schema)
  assert.equal(output, await render(schema))
  assert.match(output, /enabled: boolean/)
  assert.match(output, /label\?: string \| null/)
})

test('check detects missing output and drift without modifying it; CRLF is accepted', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'masp-contract-test-'))
  try {
    const source = join(directory, 'input.json'), target = join(directory, 'output.ts')
    await writeFile(source, JSON.stringify(schema))
    assert.equal(await sync({ source, target, check: true }), false)
    await assert.rejects(readFile(target), { code: 'ENOENT' })
    await sync({ source, target })
    const before = await readFile(target, 'utf8')
    await writeFile(target, before.replaceAll('\n', '\r\n'))
    assert.equal(await sync({ source, target, check: true }), true)
    const changed = structuredClone(schema)
    changed.components.schemas.Example.properties.enabled.type = 'string'
    await writeFile(source, JSON.stringify(changed))
    assert.equal(await sync({ source, target, check: true }), false)
    assert.equal(await readFile(target, 'utf8'), before.replaceAll('\n', '\r\n'))
  } finally {
    // This exact fresh mkdtemp directory contains only this test's two files.
    await rm(directory, { recursive: true, force: true })
  }
})

test('remote and local-file references are rejected before resolution', async () => {
  for (const ref of ['https://invalid.invalid/schema.json', 'file:///private/schema.json', '../private.json']) {
    const changed = structuredClone(schema)
    changed.components.schemas.Example = { $ref: ref }
    await assert.rejects(render(changed), /External schema references are not allowed/)
  }
})
