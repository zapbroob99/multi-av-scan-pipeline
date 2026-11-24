import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi } from 'vitest'
import type { components } from '../lib/api.generated'
import { RulePreview } from './rule-preview'

const context = { source: 'Database', scope: 'Profile', applies: 'New scans', edit_at: 'Profiles', restart: 'No restart', state: 'resolved' as const }
const configuration: components['schemas']['ClientConfiguration'] = {
  client_id: 3, client_name: 'Client', enabled: true, managed: false, observed_at: 1700000000,
  profile: { id: 7, name: 'Profile', management_revision: 2, enabled: true, is_default: true, engine_ids: [1], incomplete: false, rules_invalid: false,
    rules: { version: 2, inconclusive: 'block', rules: [{ when: { families: ['pdf'] }, action: 'block' }, { action: 'scan', engines: [1], archive: 'whole' }] } },
  header_types: [{ key: 'pdf', family: 'pdf' }, { key: 'pe', family: 'executable' }],
  upload_policy_bytes: 0, upload_policy_source: 'Default', http_body_ceiling_bytes: 67108864, http_configuration_valid: true,
  gateways: [], gateways_incomplete: false, engines: [{ id: 1, name: '<script>Scanner</script>', eligible: true, excluded_reason: null,
    pool_id: null, pool_name: null, pool_enabled: null, observations: [], observations_incomplete: false }],
  upload_policy_context: context, http_context: context, profile_context: context, placement_context: context,
}
const result: components['schemas']['RulePreview'] = { profile_id: 7, profile_revision: 2, observed_at: 1700000000,
  configuration_fingerprint: 'f'.repeat(64), status: 'matched', matches: [{ number: 2, action: 'scan', engine_ids: [1], archive: 'whole' }],
  engines: [{ id: 1, name: '<script>Scanner</script>' }],
  limits: [{ label: 'HTTP request body', state: 'unknown', explanation: 'Multipart overhead is unknown.' }], warnings: ['Not a scan or allow decision.'] }
function mount(fetcher = vi.fn(async () => new Response(JSON.stringify(result)))) {
  vi.stubGlobal('fetch', fetcher)
  const view = render(<RulePreview configuration={configuration} source="api" session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} />)
  return { fetcher, ...view }
}

describe('Saved rule preview', () => {
  it('runs only on request, sends exact metadata with CSRF and clears results after an edit', async () => {
    const { fetcher } = mount()
    await userEvent.click(screen.getByText('Try a file against saved rules'))
    expect(fetcher).not.toHaveBeenCalled()
    await userEvent.type(screen.getByLabelText('File size'), '1.5')
    await userEvent.type(screen.getByLabelText('Declared extension'), '.PDF')
    expect(screen.getByLabelText('Header content type')).toHaveValue('')
    await userEvent.click(screen.getByRole('button', { name: 'Preview saved rules' }))
    await screen.findByRole('heading', { name: 'Matches rule 2' })
    const options = (fetcher.mock.calls[0] as unknown as [string, RequestInit])[1]
    expect(JSON.parse(String(options.body))).toEqual({ profile_id: 7, expected_revision: 2, source: 'api', size_bytes: 1572864, extension: 'pdf', header_type: null })
    expect(options.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(screen.getByText(/Selected engines:/)).toHaveTextContent('<script>Scanner</script>')
    expect(document.querySelector('script')).toBeNull()
    await userEvent.selectOptions(screen.getByLabelText('Header content type'), 'pe')
    expect(screen.queryByRole('region', { name: 'Rule preview result' })).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('shows ambiguous candidates without inventing a single rule', async () => {
    mount(vi.fn(async () => new Response(JSON.stringify({ ...result, status: 'ambiguous', matches: [
      { number: 1, action: 'block', engine_ids: [], archive: null }, ...result.matches,
    ] }))))
    await userEvent.click(screen.getByText('Try a file against saved rules'))
    await userEvent.type(screen.getByLabelText('File size'), '1')
    await userEvent.click(screen.getByRole('button', { name: 'Preview saved rules' }))
    expect(await screen.findByRole('heading', { name: 'Matching rule cannot be determined' })).toBeInTheDocument()
    expect(screen.getByText('Rule 1: Block')).toBeInTheDocument()
    expect(screen.getByText('Rule 2: Scan')).toBeInTheDocument()
  })

  it('does not retry a stale profile response', async () => {
    const { fetcher } = mount(vi.fn(async () => new Response(JSON.stringify({ detail: 'Profile changed. Refresh the overview.' }), { status: 409 })))
    await userEvent.click(screen.getByText('Try a file against saved rules'))
    await userEvent.type(screen.getByLabelText('File size'), '1')
    await userEvent.click(screen.getByRole('button', { name: 'Preview saved rules' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Refresh the overview')
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('region', { name: 'Rule preview result' })).toBeNull()
  })

  it('ignores an old response arriving after metadata changes', async () => {
    let complete!: (response: Response) => void
    const { fetcher } = mount(vi.fn(() => new Promise<Response>(resolve => { complete = resolve })))
    await userEvent.click(screen.getByText('Try a file against saved rules'))
    await userEvent.type(screen.getByLabelText('File size'), '1')
    await userEvent.click(screen.getByRole('button', { name: 'Preview saved rules' }))
    await userEvent.selectOptions(screen.getByLabelText('Size unit'), 'bytes')
    const options = (fetcher.mock.calls[0] as unknown as [string, RequestInit])[1]
    expect(options.signal?.aborted).toBe(true)
    await act(async () => { complete(new Response(JSON.stringify(result))) })
    expect(screen.queryByRole('region', { name: 'Rule preview result' })).toBeNull()
  })
})
