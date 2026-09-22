import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import ScanPolicy from './scan-policy'

function mount(fail = false) {
  const fields = ['api_max_wait_seconds', 'api_retry_after_seconds', 'upload_max_bytes'].map(key => ({ key, label: key, help: 'Help',
    unit: '', minimum: 0, maximum: 5000, default: 0, value: 0, override_raw: '', source: 'default' }))
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'PUT'
    ? fail ? new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }) : new Response(null, { status: 204 })
    : new Response(JSON.stringify({ fields })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><ScanPolicy session={{ user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf' }} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Scan policy', () => {
  it('confirms all overrides including blank reset values and sends CSRF once', async () => {
    const fetcher = mount()
    await userEvent.type(await screen.findByLabelText('api_max_wait_seconds'), '30')
    await userEvent.click(screen.getByRole('button', { name: 'Review policy changes' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(screen.getByLabelText('api_max_wait_seconds')).toHaveValue(30)
    await userEvent.click(screen.getByRole('button', { name: 'Review policy changes' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm policy changes' }))
    await screen.findByText('Scan policy saved. Reload policy to see the effective values.')
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')
    expect(writes).toHaveLength(1)
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ api_max_wait_seconds: '30', api_retry_after_seconds: '', upload_max_bytes: '' })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(screen.queryByRole('form')).toBeNull()
  })
  it('requires reconciliation after an uncertain response without replay', async () => {
    const fetcher = mount(true)
    await userEvent.click(await screen.findByRole('button', { name: 'Review policy changes' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm policy changes' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('request will not be replayed')
    expect(screen.queryByRole('form')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Reload policy' }))
    expect(await screen.findByRole('button', { name: 'Review policy changes' })).toBeEnabled()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'PUT')).toHaveLength(1)
  })
})
