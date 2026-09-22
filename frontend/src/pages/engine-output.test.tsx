import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'
import EngineOutput from './engine-output'

const payload = { scan_id: 42, result_id: 7, engine_name: 'AV', attempt_count: 2,
  raw_output: '<script>alert(1)</script>', details_json: '{not json', findings_json: '[]' }

function mount(path = '/scans/42/results/7', status = 200) {
  const fetcher = vi.fn(async () => new Response(JSON.stringify(status === 200 ? payload : { detail: 'Output exceeds limit' }), { status }))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient()
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/scans/:scanId/results/:resultId" element={<EngineOutput />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  return { fetcher, client, view }
}

describe('Full engine output', () => {
  it('loads one result and renders raw output and invalid JSON as inert text', async () => {
    const { fetcher } = mount()
    expect(await screen.findByText(payload.raw_output)).toBeInTheDocument()
    expect(screen.getByText(payload.details_json)).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/scans/42/results/7/full', expect.objectContaining({ cache: 'no-store', method: 'GET' }))
    expect(screen.getByRole('link', { name: 'Back to report' })).toHaveAttribute('href', '/scans/42')
  })
  it('removes earlier output after a failed refresh and does not retry automatically', async () => {
    const { fetcher } = mount()
    await screen.findByText(payload.raw_output)
    fetcher.mockImplementationOnce(async () => new Response(JSON.stringify({ detail: 'Manual scan result not found.' }), { status: 404 }))
    await userEvent.click(screen.getByRole('button', { name: 'Refresh output' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Manual scan result not found.')
    expect(screen.queryByText(payload.raw_output)).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(2)
  })
  it('offers the plain-text download instead of the legacy report when the JSON read is refused', async () => {
    mount('/scans/42/results/7', 413)
    expect(await screen.findByRole('alert')).toHaveTextContent('Output exceeds limit')
    expect(screen.queryByRole('heading', { name: 'AV' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'legacy report' })).toBeNull()
    // Served directly by the browser: the response never enters React state.
    expect(screen.getByRole('link', { name: 'Download raw output (plain text)' }))
      .toHaveAttribute('href', '/api/ui/v1/scans/42/results/7/output')
  })
  it('rejects unsafe IDs without a request', () => {
    const { fetcher } = mount('/scans/42/results/9007199254740992')
    expect(screen.getByRole('heading', { name: 'Invalid scan or result ID' })).toBeInTheDocument()
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('discards sensitive output when leaving the screen', async () => {
    const { client, view } = mount()
    await screen.findByText(payload.raw_output)
    view.unmount()
    await vi.waitFor(() => expect(client.getQueryData(['engine-output', '42', '7'])).toBeUndefined())
  })
})
