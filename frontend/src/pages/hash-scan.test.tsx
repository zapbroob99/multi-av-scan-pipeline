import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import HashScan from './hash-scan'

function mount(fail = false) {
  const fetcher = vi.fn(async (_url: string, options?: RequestInit) => new Response(JSON.stringify(options?.method === 'POST'
    ? fail ? { detail: 'Quota exhausted' } : { sha256: 'a'.repeat(64), action: 'review', reason: 'Backend requires review',
      results: [{ id: 1, name: '<script>Engine</script>', action: 'review', found: false }] }
    : { engines: [{ id: 1, name: '<script>Engine</script>' }] }), { status: fail && options?.method === 'POST' ? 503 : 200 }))
  vi.stubGlobal('fetch', fetcher)
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><HashScan session={{ user: { id: 1, username: 'analyst', role: 'analyst' }, csrf_token: 'csrf' }} /></MemoryRouter></QueryClientProvider>)
  return fetcher
}

describe('Hash lookup', () => {
  it('posts explicitly with CSRF and displays the backend decision as inert text', async () => {
    const fetcher = mount()
    await screen.findByText(/Enabled hash engines/)
    expect(fetcher).toHaveBeenCalledTimes(1)
    await userEvent.type(screen.getByLabelText('SHA-256'), 'a'.repeat(64))
    await userEvent.click(screen.getByRole('button', { name: 'Look up hash' }))
    await screen.findByRole('heading', { name: 'Reputation decision: review' })
    expect(screen.getByText('Backend requires review')).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    const write = fetcher.mock.calls.find(([, options]) => options?.method === 'POST')!
    expect(write[1]?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf' })
    expect(JSON.parse(String(write[1]?.body))).toEqual({ sha256: 'a'.repeat(64) })
    await userEvent.clear(screen.getByLabelText('SHA-256'))
    expect(screen.queryByRole('region', { name: 'Hash lookup result' })).toBeNull()
  })
  it('does not retry failures or display an allow decision', async () => {
    const fetcher = mount(true)
    await screen.findByText(/Enabled hash engines/)
    await userEvent.type(screen.getByLabelText('SHA-256'), 'a'.repeat(64))
    await userEvent.click(screen.getByRole('button', { name: 'Look up hash' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('consumed quota')
    expect(screen.queryByRole('region', { name: 'Hash lookup result' })).toBeNull()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
  })
})
