import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ClientProfiles from './client-profiles'

const MB = 1024 * 1024
const RULES = { version: 2, inconclusive: 'block', rules: [
  { when: { larger_than_bytes: 500 * MB, up_to_bytes: null, families: [], masquerade: false }, action: 'light', engines: [2], archive: null },
  { when: { larger_than_bytes: null, up_to_bytes: null, families: [], masquerade: false }, action: 'scan', engines: [1], archive: 'whole' },
] }
const ENGINES = [
  { id: 1, display_name: 'ClamAV', adapter_key: 'clamav', enabled: true, detection: true, excluded_reason: null },
  { id: 2, display_name: 'File Type', adapter_key: 'file_type', enabled: true, detection: false, excluded_reason: null },
  { id: 3, display_name: 'VirusTotal', adapter_key: 'virustotal', enabled: true, detection: true, excluded_reason: 'Paid reputation service.' },
]

function mount({ fail = false, named = false, rules = RULES as object | null } = {}) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method && options.method !== 'GET'
    ? fail ? new Response(JSON.stringify({ detail: 'Profile changed' }), { status: 409 })
      : options.method === 'POST' ? new Response(JSON.stringify({ profile_id: 8 }), { status: 201 }) : new Response(null, { status: 204 })
    : new Response(JSON.stringify({ client_id: 3, managed: false, next_after: null, engines_incomplete: false,
      default_profile_id: named ? 6 : 7, upload_cap_bytes: 0,
      gateways: [{ port: 1344, fail_closed: true, max_bytes: 50 * MB, wait_seconds: 30 }],
      items: [{ id: 7, name: '<script>Profile</script>', enabled: true, is_default: !named, engine_ids: [1, 2], incomplete: false,
        management_revision: 4, rules, rules_invalid: rules === null }],
      engines: ENGINES })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={['/service-clients/3/profiles']}><Routes>
    <Route path="/service-clients/:clientId/profiles" element={<ClientProfiles session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  return fetcher
}

const writes = (fetcher: ReturnType<typeof mount>, method: string) => fetcher.mock.calls.filter(([, options]) => options?.method === method)
const reads = (fetcher: ReturnType<typeof mount>) => fetcher.mock.calls.filter(([, options]) => !options?.method || options.method === 'GET')

describe('Profile rules', () => {
  it('lists the rules in order with the inconclusive choice and what acts before them', async () => {
    mount()
    const section = await screen.findByRole('region', { name: 'Rules for <script>Profile</script>' })
    const rows = within(section).getAllByRole('row').slice(1)
    expect(rows.map(row => row.textContent)).toEqual(['1Larger than 500 MBLight check: File Type', '2Every other fileScan: ClamAV'])
    expect(section).toHaveTextContent('When the result is not conclusive: Block')
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByText(/ICAP gateway on port 1344: files over 50 MiB are blocked; no verdict within 30 s or MASP unreachable: blocked/)).toBeInTheDocument()
  })

  it('adds a rule above the last one and saves the whole list behind the revision fence', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Edit rules' }))
    await userEvent.click(screen.getByRole('button', { name: 'Add rule' }))
    const added = screen.getByRole('listitem', { name: 'Rule 2' })
    await userEvent.click(within(added).getByRole('checkbox', { name: 'Programs' }))
    await userEvent.selectOptions(within(added).getByRole('combobox', { name: 'Action' }), 'block')
    // The last rule stays last and keeps matching every other file.
    expect(within(screen.getByRole('listitem', { name: 'Rule 3' })).getByText('Every other file')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getAllByRole('row').slice(1).map(row => row.textContent)).toEqual(
      ['1Larger than 500 MBLight check: File Type', '2Type: ProgramsBlock', '3Every other fileScan: ClamAV'])
    expect(writes(fetcher, 'PUT')).toHaveLength(0)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save rules' }))
    await screen.findByText('Rules saved.')
    const [[url, options]] = writes(fetcher, 'PUT')
    expect(url).toBe('/api/ui/v1/service-clients/3/profiles/7/policy')
    expect(options?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    const body = JSON.parse(String(options?.body))
    expect(body.expected_revision).toBe(4)
    expect(body.rules.rules[1]).toEqual({ when: { larger_than_bytes: null, up_to_bytes: null, families: ['executable'], masquerade: false },
      action: 'block', engines: [], archive: null })
    expect(body.rules.inconclusive).toBe('block')
    // One fresh read after the save, never a second write.
    expect(reads(fetcher)).toHaveLength(2)
  })

  it('moves rules, and offers only the engines that fit each action', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Edit rules' }))
    await userEvent.click(screen.getByRole('button', { name: 'Add rule' }))
    const added = screen.getByRole('listitem', { name: 'Rule 2' })
    await userEvent.type(within(added).getByLabelText('Up to (MB)'), '5')
    await userEvent.selectOptions(within(added).getByRole('combobox', { name: 'Action' }), 'light')
    // A light check offers only checks; paid reputation services never appear.
    const engines = within(within(added).getByRole('group', { name: 'Engines' })).getAllByRole('checkbox')
    expect(engines.map(box => box.parentElement?.textContent)).toEqual(['File Type'])
    await userEvent.click(engines[0])
    await userEvent.click(screen.getByRole('button', { name: 'Move rule 2 up' }))
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save rules' }))
    await screen.findByText('Rules saved.')
    const body = JSON.parse(String(writes(fetcher, 'PUT')[0][1]?.body))
    expect(body.rules.rules.map((rule: { action: string }) => rule.action)).toEqual(['light', 'light', 'scan'])
    expect(body.rules.rules[0].when.up_to_bytes).toBe(5 * MB)
  })

  it('refuses incomplete rules in the browser without a request', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Edit rules' }))
    await userEvent.click(screen.getByRole('button', { name: 'Add rule' }))
    const added = screen.getByRole('listitem', { name: 'Rule 2' })
    await userEvent.selectOptions(within(added).getByRole('combobox', { name: 'Action' }), 'block')
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Rule 2: give it a condition; only the last rule matches every file.')
    await userEvent.click(within(added).getByRole('checkbox', { name: 'Scripts' }))
    await userEvent.selectOptions(within(added).getByRole('combobox', { name: 'Action' }), 'scan')
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Rule 2: choose at least one engine.')
    await userEvent.click(within(added).getByRole('checkbox', { name: 'File Type' }))
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Rule 2: Scan needs at least one antivirus')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('says when stored rules cannot be read and starts the editor empty', async () => {
    mount({ rules: null })
    expect(await screen.findByText(/This profile has no readable rules/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Edit rules' }))
    expect(screen.getByText(/Saving replaces whatever is stored/)).toBeInTheDocument()
    expect(screen.getAllByRole('listitem')).toHaveLength(1)
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Action' }), 'block')
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    expect(screen.getByText('Choose what happens when the result is not conclusive.')).toHaveAttribute('role', 'alert')
  })

  it('requires reconciliation after a stale or uncertain write, without replay', async () => {
    const fetcher = mount({ fail: true })
    await userEvent.click(await screen.findByRole('button', { name: 'Edit rules' }))
    await userEvent.click(screen.getByRole('button', { name: 'Review rules' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save rules' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Profile changed')
    expect(screen.queryByRole('button', { name: 'Edit rules' })).toBeNull()
    expect(writes(fetcher, 'PUT')).toHaveLength(1)
    expect(reads(fetcher)).toHaveLength(1)
  })
})

describe('Profile management', () => {
  it('creates a profile only with chosen engines and an explicit inconclusive choice', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Add profile' }))
    await userEvent.type(screen.getByLabelText('Profile name'), 'Fast')
    expect(screen.queryByRole('checkbox', { name: 'VirusTotal' })).toBeNull()
    await userEvent.click(screen.getByRole('checkbox', { name: 'ClamAV' }))
    await userEvent.selectOptions(screen.getByLabelText('When the result is not conclusive'), 'allow')
    await userEvent.click(screen.getByRole('button', { name: 'Review profile' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Its one rule sends every file to ClamAV; an inconclusive result is allowed and labelled.')
    await userEvent.click(screen.getByRole('button', { name: 'Confirm profile change' }))
    await screen.findByText('Profile created.')
    const [[, options]] = writes(fetcher, 'POST')
    expect(JSON.parse(String(options?.body))).toEqual({ name: 'Fast', engine_ids: [1], inconclusive: 'allow' })
  })
  it('protects the default profile from disable and delete', async () => {
    mount()
    expect(await screen.findByRole('button', { name: 'Delete profile' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Make default' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Rename or disable' }))
    expect(screen.getByLabelText('Profile state')).toBeDisabled()
  })
  it.each(['default', 'delete'] as const)('confirms a %s operation with the displayed revision', async kind => {
    const fetcher = mount({ named: true })
    await userEvent.click(await screen.findByRole('button', { name: kind === 'default' ? 'Make default' : 'Delete profile' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm profile change' }))
    await screen.findByText(kind === 'default' ? 'Default profile changed.' : 'Profile deleted.')
    const sent = writes(fetcher, kind === 'default' ? 'PUT' : 'DELETE')
    expect(sent).toHaveLength(1)
    expect(sent[0][0]).toBe('/api/ui/v1/service-clients/3/profiles/7' + (kind === 'default' ? '/default' : ''))
    expect(JSON.parse(String(sent[0][1]?.body))).toEqual(kind === 'default'
      ? { expected_revision: 4, expected_default_profile_id: 6 } : { expected_revision: 4 })
  })
  it('renames and disables a named profile with its revision', async () => {
    const fetcher = mount({ named: true })
    await userEvent.click(await screen.findByRole('button', { name: 'Rename or disable' }))
    await userEvent.clear(screen.getByLabelText('Profile name'))
    await userEvent.type(screen.getByLabelText('Profile name'), 'Renamed')
    await userEvent.selectOptions(screen.getByLabelText('Profile state'), 'disabled')
    await userEvent.click(screen.getByRole('button', { name: 'Review profile' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm profile change' }))
    await screen.findByText('Profile saved.')
    expect(JSON.parse(String(writes(fetcher, 'PUT')[0][1]?.body))).toEqual({ name: 'Renamed', enabled: false, expected_revision: 4 })
  })
})
