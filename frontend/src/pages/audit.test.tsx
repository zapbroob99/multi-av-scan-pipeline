import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import Audit from './audit'

const EVENT = {
  id: 42, created_at: '2026-09-20 10:00:00', actor_type: 'user', actor_id: '3', actor_name: '<script>alice</script>',
  action: 'user.delete', target_type: 'user', target_id: '9', outcome: 'denied', source_ip: '127.0.0.1',
  request_id: 'req-abc', details: '{"reason": "<b>last admin</b>"}', details_truncated: true,
}

function mount() {
  const fetcher = vi.fn(async () => new Response(JSON.stringify({ items: [EVENT], next_before: 42 })))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><Audit /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Audit trail', () => {
  it('renders recorded values as inert text and keeps the page bounded without a total', async () => {
    const fetcher = mount()
    await screen.findByText('user.delete')
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/audit?limit=20', expect.anything())
    expect(screen.getByText(/<script>alice<\/script>/)).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByLabelText('Audit event 42 details text')).toHaveTextContent('{"reason": "<b>last admin</b>"}')
    expect(document.querySelector('b')).toBeNull()
    expect(screen.getByText('Details truncated for display.')).toBeInTheDocument()
    expect(screen.queryByText(/events? total/i)).toBeNull()
  })

  it('sends filters and the keyset cursor without polling', async () => {
    const fetcher = mount()
    await screen.findByText('user.delete')
    await userEvent.type(screen.getByLabelText('Actor, action, target or request ID'), '100%')
    await userEvent.selectOptions(screen.getByLabelText('Outcome'), 'denied')
    await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/audit?q=100%25&outcome=denied&limit=20', expect.anything()))
    await userEvent.click(screen.getByRole('button', { name: 'Older events' }))
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/audit?q=100%25&outcome=denied&before=42&limit=20', expect.anything()))
    const calls = fetcher.mock.calls.length
    await new Promise(resolve => setTimeout(resolve, 60))
    expect(fetcher.mock.calls).toHaveLength(calls)
  })

  it('reports a read failure instead of presenting an empty trail as clean', async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ detail: 'Budget exceeded' }), { status: 503 }))
    vi.stubGlobal('fetch', fetcher)
    render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><Audit /></MemoryRouter></QueryClientProvider>)
    await screen.findByRole('alert')
    expect(screen.getByRole('alert')).toHaveTextContent('Budget exceeded')
    expect(screen.queryByText('No audit events match these filters.')).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
})
