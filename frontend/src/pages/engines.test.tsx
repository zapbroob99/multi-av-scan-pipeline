import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Engines, { ConfigFields } from './engines'
import { pollInterval, type Adapter, type Inventory } from '../lib/api'

const adapter: Adapter = { key: 'clamav', label: 'ClamAV', description: 'TCP adapter', support_state: 'supported',
  capabilities: { deployment: 'worker', supports_rules: false, consumes_external_quota: false, allows_multiple_instances: true,
    input_modes: ['file'], supported_platforms: ['linux'], execution_model: 'local', supports_file_upload: true, supports_hash_lookup: false },
  fields: [
    { key: 'mode', label: 'Connection mode', field_type: 'text', required: true, default: 'clamd', secret: false, help_text: '', choices: ['clamd', 'cli'] },
    { key: 'timeout_seconds', label: 'Timeout', field_type: 'number', required: true, default: '60', secret: false, help_text: '', choices: [] },
  ] }
const makeInventory = (): Inventory => ({ adapters: [adapter], pools: [], engines: [{
  id: 42, adapter_key: 'clamav', display_name: 'ClamAV Istanbul', enabled: true,
  config: { mode: 'clamd', timeout_seconds: '60' }, has_secret: false, pool_id: null,
  health: { state: 'healthy', ok: true, detail: 'Previous successful check', checked_at: 100 },
}] })
const session = { user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'test-csrf' }

function mount(fetcher: typeof fetch) {
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><MemoryRouter><Engines session={session} /></MemoryRouter></QueryClientProvider>)
}

describe('Engine console', () => {
  it('does not turn suggested config into saved defaults', () => {
    render(<ConfigFields adapter={adapter} values={{}} onChange={() => {}} />)
    expect(screen.getByRole('combobox')).toHaveValue('')
    expect(screen.getByPlaceholderText('60')).toHaveValue(null)
  })

  it('requires an explicit adapter choice before showing a create form', async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify(makeInventory())))
    mount(fetcher)
    await screen.findByText('ClamAV Istanbul')
    await userEvent.click(screen.getByRole('button', { name: 'Add engine' }))
    expect(screen.queryByLabelText('Deployment name')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'ClamAV supported' }))
    expect(screen.getByLabelText('Deployment name')).toHaveValue('')
    expect(screen.getByLabelText('Connection mode')).toHaveValue('')
    expect(fetcher.mock.calls).toHaveLength(1)
  })

  it('shows a requested worker check as pending, never successful', async () => {
    const data = makeInventory()
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/checks')) {
        expect(init?.method).toBe('POST')
        expect((init?.headers as Record<string, string>)['X-CSRF-Token']).toBe('test-csrf')
        data.engines[0].health = { state: 'pending', ok: false, detail: 'Waiting for worker', checked_at: null }
        return new Response(JSON.stringify(data.engines[0].health), { status: 202 })
      }
      return new Response(JSON.stringify(data))
    })
    mount(fetcher)
    await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }))
    await screen.findByText('pending')
    expect(screen.getByRole('status')).toHaveTextContent('not a connection success')
    expect(screen.queryByText('healthy')).not.toBeInTheDocument()
  })

  it('retains settings and displays server validation errors inside the modal', async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
      new Response(JSON.stringify(init?.method === 'PUT' ? { detail: 'Invalid engine configuration.' } : makeInventory()),
        { status: init?.method === 'PUT' ? 422 : 200 }))
    mount(fetcher)
    await userEvent.click(await screen.findByRole('button', { name: 'Settings for ClamAV Istanbul' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    await waitFor(() => expect(screen.getByRole('dialog')).toHaveTextContent('Invalid engine configuration.'))
    expect(screen.getByLabelText('Connection mode')).toHaveValue('clamd')
  })

  it('renders server strings as text instead of executable markup', async () => {
    const data = makeInventory()
    data.engines[0].health.detail = '<img src=x onerror=alert(1)>'
    mount(vi.fn(async () => new Response(JSON.stringify(data))))
    await screen.findByText('<img src=x onerror=alert(1)>')
    expect(document.querySelector('.health-detail img')).toBeNull()
  })

  it('shows field help outside the label, readable choices and sizes', () => {
    const sized: Adapter = { ...adapter, fields: [adapter.fields[0],
      { key: 'timeout_seconds', label: 'Timeout (seconds)', field_type: 'number', required: true, default: '60', secret: false, help_text: 'A scan that takes longer is recorded as failed.', choices: [] },
      { key: 'max_file_size_bytes', label: 'Largest file to scan (bytes)', field_type: 'number', required: true, default: '0', secret: false, help_text: 'ClamAV skips larger files.', choices: [] }] }
    render(<ConfigFields adapter={sized} values={{ mode: 'clamd', max_file_size_bytes: '52428800' }} onChange={() => {}} />)
    expect(screen.getByLabelText('Timeout (seconds)')).toHaveAccessibleDescription('A scan that takes longer is recorded as failed.')
    expect(screen.getByLabelText('Largest file to scan (bytes)')).toHaveAccessibleDescription('ClamAV skips larger files. = 50 MiB')
    expect(screen.getByRole('option', { name: 'clamd service (network)' })).toHaveValue('clamd')
  })

  it('asks before moving an engine to another worker pool', async () => {
    const data = { ...makeInventory(), pools: [{ id: 3, name: 'Windows', enabled: true }] }
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
      init?.method === 'PUT' ? new Response(null, { status: 204 }) : new Response(JSON.stringify(data)))
    mount(fetcher)
    await userEvent.selectOptions(await screen.findByLabelText('Worker pool for ClamAV Istanbul'), '3')
    const puts = () => fetcher.mock.calls.filter(([, init]) => init?.method === 'PUT')
    expect(puts()).toHaveLength(0)
    expect(screen.getByRole('dialog')).toHaveTextContent('ClamAV Istanbul will run on the Windows pool only.')
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(puts()).toHaveLength(0)
    await userEvent.selectOptions(screen.getByLabelText('Worker pool for ClamAV Istanbul'), '3')
    await userEvent.click(screen.getByRole('button', { name: 'Change worker pool' }))
    await screen.findByText('Worker pool saved. Health will be checked again.')
    expect(puts()).toHaveLength(1)
    expect(JSON.parse(String(puts()[0][1]?.body))).toEqual({ pool_id: 3 })
  })

  it('uses slower polling when no check is in flight', () => {
    const data = makeInventory()
    expect(pollInterval(data)).toBe(30000)
    data.engines[0].health.state = 'pending'
    expect(pollInterval(data)).toBe(3000)
    data.engines[0].enabled = false
    expect(pollInterval(data)).toBe(30000)
  })
})
