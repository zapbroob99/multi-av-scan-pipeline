import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Exceptions from './exceptions'
import type { Session } from '../lib/api'

const A = 'a'.repeat(64), B = 'b'.repeat(64)
const SESSION = { csrf_token: 'csrf', user: { id: 1, username: 'admin', role: 'admin' } } as unknown as Session
const ITEM = { id: 5, sha256: A, client_id: null, client_name: null, reason: '<b>Vendor installer</b>', created_by: 'admin',
  created_at: 1790000000, expires_at: null, revoked_by: null, revoked_at: null, state: 'active', uses: 3 }
const CLIENTS = { items: [{ id: 3, client_key: 'gate', display_name: 'Gateway' }] }

function mount(path = '/engines/exceptions') {
  const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.startsWith('/api/ui/v1/api-ledger/clients')) return new Response(JSON.stringify(CLIENTS))
    if (init?.method === 'POST' && url.endsWith('/revoke')) return new Response(null, { status: 204 })
    if (init?.method === 'POST') return new Response(JSON.stringify({ id: 6 }), { status: 201 })
    return new Response(JSON.stringify({ items: [ITEM], next_before: 5 }))
  })
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={[path]}><Exceptions session={SESSION} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

function posted(fetcher: ReturnType<typeof mount>, suffix = '/exceptions') {
  return fetcher.mock.calls.filter(([url, init]) => init?.method === 'POST' && String(url).endsWith(suffix))
}

describe('Exceptions', () => {
  it('lists exceptions as inert text with scope, use count and a keyset cursor', async () => {
    const fetcher = mount()
    await screen.findByText(A)
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/exceptions?limit=20', expect.anything())
    expect(screen.getByText('<b>Vendor installer</b>')).toBeInTheDocument()
    expect(document.querySelector('td b')).toBeNull()
    expect(screen.getAllByText('All clients and manual scans').length).toBeGreaterThan(1)
    expect(screen.getByRole('link', { name: '3' })).toHaveAttribute('href', `/api-ledger?q=${A}`)
    await userEvent.click(screen.getByRole('button', { name: 'Older exceptions' }))
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/exceptions?before=5&limit=20', expect.anything()))
  })

  it('prefills from a report, requires a reason and adds only after confirmation', async () => {
    const fetcher = mount(`/engines/exceptions?add=${B.toUpperCase()}&client=3`)
    await screen.findByText(A)
    expect(screen.getByLabelText('SHA-256')).toHaveValue(B)
    await waitFor(() => expect(screen.getByLabelText('Applies to')).toHaveValue('3'))
    // The prefill parameters never reach the list query.
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/exceptions?limit=20', expect.anything())
    await userEvent.click(screen.getByRole('button', { name: 'Review exception' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    await userEvent.type(screen.getByLabelText('Reason'), 'Ticket 41: signed vendor build')
    await userEvent.selectOptions(screen.getByLabelText('Expires'), '30')
    await userEvent.click(screen.getByRole('button', { name: 'Review exception' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('#3 Gateway')
    expect(dialog).toHaveTextContent('30 days')
    expect(posted(fetcher)).toHaveLength(0)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm exception' }))
    await waitFor(() => expect(posted(fetcher)).toHaveLength(1))
    expect(JSON.parse(String(posted(fetcher)[0][1]!.body))).toEqual(
      { sha256: B, reason: 'Ticket 41: signed vendor build', service_client_id: 3, expires_in_days: 30 })
    expect(await screen.findByText(/Exception #6 added/)).toBeInTheDocument()
    expect(screen.getByLabelText('SHA-256')).toHaveValue('')
  }, 15000)

  it('refuses a partial digest without sending it', async () => {
    const fetcher = mount()
    await screen.findByText(A)
    await userEvent.type(screen.getByLabelText('SHA-256'), 'abc')
    await userEvent.type(screen.getByLabelText('Reason'), 'x')
    await userEvent.click(screen.getByRole('button', { name: 'Review exception' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('full SHA-256')
    expect(posted(fetcher)).toHaveLength(0)
  })

  it('revokes only after confirmation', async () => {
    const fetcher = mount()
    await screen.findByText(A)
    await userEvent.click(screen.getByRole('button', { name: 'Revoke exception 5' }))
    const dialog = await screen.findByRole('dialog')
    expect(posted(fetcher, '/revoke')).toHaveLength(0)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm revocation' }))
    await waitFor(() => expect(posted(fetcher, '/revoke')).toHaveLength(1))
    expect(String(posted(fetcher, '/revoke')[0][0])).toBe('/api/ui/v1/exceptions/5/revoke')
    expect(await screen.findByText(/Exception #5 revoked/)).toBeInTheDocument()
  })
})
