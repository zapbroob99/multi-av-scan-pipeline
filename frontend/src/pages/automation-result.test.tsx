import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { expect, it, vi } from 'vitest'
import AutomationResult from './automation-result'

it('renders inert JSON, clears failed refreshes and discards output on exit', async () => {
  const content = '{"filename":"<script>alert(1)</script>"}'
  const fetcher = vi.fn(async () => new Response(JSON.stringify({ scan_id: 42, content })))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient()
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/scans/42']}><Routes>
    <Route path="/scans/:scanId" element={<AutomationResult />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  expect(await screen.findByLabelText('Integration result JSON text')).toHaveTextContent(content)
  expect(document.querySelector('script')).toBeNull()
  expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/api-ledger/scans/42/result-json', expect.objectContaining({ cache: 'no-store' }))
  fetcher.mockImplementationOnce(async () => new Response(JSON.stringify({ detail: 'Result is not ready.' }), { status: 409 }))
  await userEvent.click(screen.getByRole('button', { name: 'Refresh JSON' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Result is not ready.')
  expect(screen.queryByLabelText('Integration result JSON text')).toBeNull()
  expect(fetcher).toHaveBeenCalledTimes(2)
  view.unmount()
  await vi.waitFor(() => expect(client.getQueryData(['automation-result-json', '42', 'result'])).toBeUndefined())
})


it('loads status independently and never polls or reuses result JSON', async () => {
  const fetcher = vi.fn(async () => new Response(JSON.stringify({ scan_id: 42, content: '{"result_ready":false}' })))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient()
  client.setQueryData(['automation-result-json', '42', 'result'], { scan_id: 42, content: 'old result' })
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/scans/42']}><Routes>
    <Route path="/scans/:scanId" element={<AutomationResult status />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  expect(await screen.findByLabelText('Integration status JSON text')).toHaveTextContent('"result_ready":false')
  expect(screen.queryByText('old result')).toBeNull()
  expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/api-ledger/scans/42/status-json', expect.objectContaining({ method: 'GET' }))
  const options = client.getQueryCache().find({ queryKey: ['automation-result-json', '42', 'status'] })?.options
  expect(options).toMatchObject({ refetchInterval: false, retry: false, gcTime: 0 })
  view.unmount()
  await vi.waitFor(() => expect(client.getQueryData(['automation-result-json', '42', 'status'])).toBeUndefined())
})
