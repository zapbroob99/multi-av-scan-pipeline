import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import WorkerPools from './worker-pools'

function mount({ assigned = false, incomplete = false } = {}) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => options?.method === 'DELETE'
    ? new Response(null, { status: 204 }) : new Response(JSON.stringify(options?.method === 'POST' || options?.method === 'PUT' ? { id: 7 }
      : { items: [{ id: 7, name: '<script>Pool</script>', selector: '{"site":"lab"}', enabled: true,
        has_assignments: assigned, metadata_incomplete: incomplete }], next_after: 7 })))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter><WorkerPools session={{
    user: { id: 1, username: 'admin', role: 'admin' }, csrf_token: 'csrf',
  }} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Worker pools', () => {
  it('confirms creation with the exact typed name and selector and CSRF', async () => {
    const fetcher = mount()
    await screen.findByRole('heading', { name: '<script>Pool</script>' })
    expect(document.querySelector('script')).toBeNull()
    const form = within(screen.getByRole('form', { name: 'Create worker pool' }))
    await userEvent.type(form.getByLabelText('Pool name'), 'New pool')
    await userEvent.type(form.getByLabelText('Label selector'), 'site=lab')
    await userEvent.click(form.getByRole('button', { name: 'Create pool' }))
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0)
    expect(screen.getByRole('dialog')).toHaveTextContent('site=lab')
    await userEvent.click(screen.getByRole('button', { name: 'Confirm pool change' }))
    await screen.findByText(/Created pool #7/)
    const writes = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(writes).toHaveLength(1)
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ name: 'New pool', selector: 'site=lab' })
    expect(writes[0][1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
  })
  it('submits an explicit disabled state for the selected pool only', async () => {
    const fetcher = mount()
    const form = within(await screen.findByRole('form', { name: 'Edit pool 7' }))
    const draftName = within(screen.getByRole('form', { name: 'Create worker pool' })).getByLabelText('Pool name')
    await userEvent.type(draftName, 'Unsaved draft')
    await userEvent.selectOptions(form.getByLabelText('Pool state'), 'disabled')
    await userEvent.click(form.getByRole('button', { name: 'Save pool' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Disabled')
    await userEvent.click(screen.getByRole('button', { name: 'Confirm pool change' }))
    await screen.findByText('Updated pool #7.')
    expect(draftName).toHaveValue('Unsaved draft')
    const write = fetcher.mock.calls.find(([, options]) => options?.method === 'PUT')!
    expect(write[0]).toBe('/api/ui/v1/system/pools/7')
    expect(JSON.parse(String(write[1]?.body))).toMatchObject({ enabled: false })
  })
  it('blocks assigned deletion and editing incomplete routing metadata', async () => {
    mount({ assigned: true, incomplete: true })
    expect(await screen.findByRole('button', { name: 'Delete pool' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save pool' })).toBeDisabled()
  })
  it('cancels deletion without writes and never retries an uncertain failure', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Delete pool' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'DELETE')).toHaveLength(0)
    await userEvent.click(screen.getByRole('button', { name: 'Delete pool' }))
    fetcher.mockImplementation(async () => new Response(JSON.stringify({ detail: 'Unavailable' }), { status: 503 }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm pool change' }))
    await screen.findByText(/request may have reached the server/)
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Delete pool' })).toBeNull())
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'DELETE')).toHaveLength(1)
  })
  it('uses the server cursor for pagination', async () => {
    const fetcher = mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Next pools' }))
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/system/pools?limit=20&after=7', expect.anything()))
  })
})
