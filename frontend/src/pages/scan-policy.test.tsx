import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ScanPolicy from './scan-policy'

const FIELDS = [
  { key: 'api_max_wait_seconds', label: 'API wait for a result', unit: 'seconds', control: 'number', minimum: 0, maximum: 300, default: 15, value: 15, override_raw: '', source: 'default' },
  { key: 'api_retry_after_seconds', label: 'API poll interval', unit: 'seconds', control: 'number', minimum: 1, maximum: 30, default: 2, value: 2, override_raw: '', source: 'default' },
  { key: 'upload_max_bytes', label: 'Largest upload', unit: 'bytes', control: 'size', minimum: 0, maximum: 5368709120, default: 0, value: 2097152, override_raw: '2097152', source: 'database override' },
  { key: 'siem_not_allowed_events', label: 'Send not-allowed files to SIEM', unit: '', control: 'switch', minimum: 0, maximum: 1, default: 0, value: 0, override_raw: '', source: 'default' },
].map(field => ({ ...field, help: `Help for ${field.label}` }))

function mount(fail = false) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'PUT'
    ? fail ? new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }) : new Response(null, { status: 204 })
    : new Response(JSON.stringify({ fields: FIELDS })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><ScanPolicy session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

const reads = (fetcher: ReturnType<typeof mount>) => fetcher.mock.calls.filter(([, options]) => !options?.method || options.method === 'GET')
const writes = (fetcher: ReturnType<typeof mount>) => fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')

describe('System limits and notifications', () => {
  it('edits sizes in MiB, offers the switch as on, off or not set, and saves bytes once', async () => {
    const fetcher = mount()
    const size = await screen.findByLabelText('Largest upload (MiB)')
    expect(size).toHaveValue('2')
    expect(size).toHaveAccessibleDescription('Help for Largest upload')
    expect(screen.getByText('2.0 MiB')).toBeInTheDocument()
    const siem = screen.getByLabelText('Send not-allowed files to SIEM')
    expect(siem).toHaveValue('')
    expect(screen.getByRole('option', { name: 'Not set here (Off)' })).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('API wait for a result (seconds)'), '30')
    await userEvent.clear(size)
    await userEvent.type(size, '1.5')
    await userEvent.selectOptions(siem, '1')
    await userEvent.click(screen.getByRole('button', { name: 'Review changes' }))
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('1.5 MiB')
    expect(dialog).toHaveTextContent('Send not-allowed files to SIEMOn')
    expect(dialog).toHaveTextContent('API poll intervalNot set here (2 seconds)')
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(writes(fetcher)).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: 'Review changes' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    await screen.findByText('Settings saved. The values below are the ones now in effect.')
    expect(writes(fetcher)).toHaveLength(1)
    expect(JSON.parse(String(writes(fetcher)[0][1]?.body))).toEqual({
      api_max_wait_seconds: '30', api_retry_after_seconds: '', upload_max_bytes: '1572864', siem_not_allowed_events: '1' })
    expect(writes(fetcher)[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    // The saved values come back through one fresh read; the form is shown again.
    expect(reads(fetcher)).toHaveLength(2)
    expect(await screen.findByRole('form', { name: 'System limits and notifications' })).toBeInTheDocument()
  })
  it('refuses a size that is not a number without a request', async () => {
    const fetcher = mount()
    const size = await screen.findByLabelText('Largest upload (MiB)')
    await userEvent.clear(size)
    await userEvent.type(size, 'lots')
    await userEvent.click(screen.getByRole('button', { name: 'Review changes' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Largest upload: enter a size in MiB')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
  it('requires reconciliation after an uncertain response without replay', async () => {
    const fetcher = mount(true)
    await userEvent.click(await screen.findByRole('button', { name: 'Review changes' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('request will not be replayed')
    expect(screen.queryByRole('form')).toBeNull()
    expect(reads(fetcher)).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Reload' }))
    expect(await screen.findByRole('button', { name: 'Review changes' })).toBeEnabled()
    expect(writes(fetcher)).toHaveLength(1)
  })
})
