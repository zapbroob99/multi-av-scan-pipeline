import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ClientProfiles from './client-profiles'

const INHERIT = { max_file_bytes: null, type_rule: null, block_masquerade: false, violation_action: 'scan_and_block', review_action: 'inherit' }

function mount(incomplete = false, fail = false, named = false, policy: object | null = INHERIT) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method && options.method !== 'GET'
    ? fail ? new Response(JSON.stringify({ detail: 'Routing changed' }), { status: 409 })
      : options.method === 'POST' ? new Response(JSON.stringify({ profile_id: 8 }), { status: 201 }) : new Response(null, { status: 204 })
    : new Response(JSON.stringify({ client_id: 3, managed: false, next_after: null, engines_incomplete: incomplete,
      default_profile_id: named ? 6 : 7,
      items: [{ id: 7, name: '<script>Profile</script>', enabled: true, is_default: !named, engine_ids: [1], incomplete: false, management_revision: 4,
        policy, policy_invalid: policy === null }],
      engines: [{ id: 1, display_name: 'One', adapter_key: 'static_metadata', enabled: true }, { id: 2, display_name: 'Two', adapter_key: 'clamav', enabled: false }] })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={['/service-clients/3/profiles']}><Routes>
    <Route path="/service-clients/:clientId/profiles" element={<ClientProfiles session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Profile scan policy', () => {
  it('shows an inheriting policy and saves an edited one behind the revision fence', async () => {
    const fetcher = mount()
    const section = await screen.findByRole('region', { name: 'File rules for <script>Profile</script>' })
    expect(section).toHaveTextContent("No rules of its own: the server's limits and review handling apply.")
    await userEvent.click(screen.getByRole('button', { name: 'Edit rules' }))
    await userEvent.type(screen.getByLabelText(/^Largest accepted file/), '5')
    await userEvent.selectOptions(screen.getByLabelText(/^Content rule/), 'denylist')
    await userEvent.click(screen.getByRole('checkbox', { name: /extension contradicts their content/ }))
    await userEvent.selectOptions(screen.getByLabelText('When content is not accepted'), 'reject')
    await userEvent.selectOptions(screen.getByLabelText(/^Files that could not be fully assessed/), 'block')
    await userEvent.selectOptions(screen.getByLabelText(/^Archive handling/), 'inspect')
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')).toHaveLength(0)
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('Files larger than 5.0 MiB are rejected.')
    expect(dialog).toHaveTextContent('Not accepted: executable, script.')
    expect(dialog).toHaveTextContent('Files that could not be fully assessed are blocked.')
    expect(dialog).toHaveTextContent('Archives are opened and checked')
    await userEvent.click(screen.getByRole('button', { name: 'Save file rules' }))
    await screen.findByText('File rules saved.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')
    expect(writes).toHaveLength(1)
    expect(writes[0][0]).toBe('/api/ui/v1/service-clients/3/profiles/7/policy')
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ expected_revision: 4, policy: {
      max_file_bytes: 5242880, type_rule: { mode: 'denylist', families: ['executable', 'script'] },
      block_masquerade: true, violation_action: 'reject', review_action: 'block', archive_handling: 'inspect' } })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
  })
  it('says when a stored policy cannot be read instead of guessing one', async () => {
    mount(false, false, false, null)
    expect(await screen.findByText(/The stored rules cannot be read/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Edit rules' }))
    expect(screen.getByText('The stored rules cannot be read. Saving replaces them with the rules below.')).toBeInTheDocument()
  })
  it('refuses a rule that would accept nothing or everything, without a request', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Edit rules' }))
    await userEvent.selectOptions(screen.getByLabelText(/^Content rule/), 'allowlist')
    for (const box of screen.getAllByRole('checkbox', { checked: true })) await userEvent.click(box)
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    expect(screen.getByText('Choose at least one content family, or turn the content rule off.')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText(/^Largest accepted file/), '0')
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    expect(screen.getByText('Enter a size in MiB greater than zero, or leave it blank.')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
  it('offers archive handling alone and asks what refused archives do', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Edit rules' }))
    expect(screen.queryByLabelText('When content is not accepted')).toBeNull()
    await userEvent.selectOptions(screen.getByLabelText(/^Archive handling/), 'scan_members')
    expect(screen.getByLabelText('When content is not accepted')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Every file inside an archive is scanned; an archive is allowed only when all of them are.')
    await userEvent.click(screen.getByRole('button', { name: 'Save file rules' }))
    await screen.findByText('File rules saved.')
    const write = fetcher.mock.calls.find(([, options]) => options?.method === 'PUT')
    expect(JSON.parse(String(write?.[1]?.body)).policy).toEqual({ ...INHERIT, archive_handling: 'scan_members' })
  })
})

describe('Profile engines', () => {
  it('confirms explicit instance IDs and sends the previous selection as a fence', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('checkbox', { name: /Two/ }))
    expect(document.querySelector('script')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Review engine changes' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Adds: Two.')
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(fetcher).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByRole('button', { name: 'Review engine changes' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save engines' }))
    await screen.findByText('Engines saved.')
    // A successful write is followed by one fresh read, never by a second write.
    expect(fetcher.mock.calls.filter(([, options]) => !options?.method || options.method === 'GET')).toHaveLength(2)
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')
    expect(writes).toHaveLength(1)
    expect(writes[0][0]).toBe('/api/ui/v1/service-clients/3/profiles/7/engines')
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ engine_ids: [1, 2], expected_engine_ids: [1], expected_revision: 4 })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
  })
  it('blocks edits from an incomplete engine inventory', async () => {
    mount(true)
    expect(await screen.findByRole('checkbox', { name: /One/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Review engine changes' })).toBeDisabled()
  })
  it('requires reconciliation after stale or uncertain writes without replay', async () => {
    const fetcher = mount(false, true)
    await userEvent.click(await screen.findByRole('checkbox', { name: /Two/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Review engine changes' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save engines' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Routing changed')
    expect(screen.queryByRole('checkbox')).toBeNull()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')).toHaveLength(1)
  })
  it('creates a named profile only after an explicit engine selection and confirmation', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Add profile' }))
    await userEvent.type(screen.getByLabelText('Profile name'), 'Fast')
    await userEvent.click(screen.getByRole('button', { name: 'Review profile' }))
    expect(screen.getByRole('button', { name: 'Confirm profile change' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await userEvent.click(screen.getAllByRole('checkbox', { name: /One/ })[0])
    await userEvent.click(screen.getByRole('button', { name: 'Review profile' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm profile change' }))
    await screen.findByText('Profile created.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(writes).toHaveLength(1)
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ name: 'Fast', engine_ids: [1] })
    expect(await screen.findByRole('button', { name: 'Rename or disable' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Add profile' })).toBeEnabled()
  })
  it('protects the default profile from disable and delete', async () => {
    mount()
    expect(await screen.findByRole('button', { name: 'Delete profile' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Make default' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Rename or disable' }))
    expect(screen.getByLabelText('Profile state')).toBeDisabled()
  })
  it.each(['default', 'delete'] as const)('confirms a %s operation with the displayed revision', async kind => {
    const fetcher = mount(false, false, true)
    await userEvent.click(await screen.findByRole('button', { name: kind === 'default' ? 'Make default' : 'Delete profile' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm profile change' }))
    await screen.findByText(kind === 'default' ? 'Default profile changed.' : 'Profile deleted.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === (kind === 'default' ? 'PUT' : 'DELETE'))
    expect(writes).toHaveLength(1)
    expect(writes[0][0]).toBe('/api/ui/v1/service-clients/3/profiles/7' + (kind === 'default' ? '/default' : ''))
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual(kind === 'default'
      ? { expected_revision: 4, expected_default_profile_id: 6 } : { expected_revision: 4 })
  })
  it('renames and disables a named profile with its revision', async () => {
    const fetcher = mount(false, false, true)
    await userEvent.click(await screen.findByRole('button', { name: 'Rename or disable' }))
    await userEvent.clear(screen.getByLabelText('Profile name'))
    await userEvent.type(screen.getByLabelText('Profile name'), 'Renamed')
    await userEvent.selectOptions(screen.getByLabelText('Profile state'), 'disabled')
    await userEvent.click(screen.getByRole('button', { name: 'Review profile' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm profile change' }))
    await screen.findByText('Profile saved.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ name: 'Renamed', enabled: false, expected_revision: 4 })
  })
})
