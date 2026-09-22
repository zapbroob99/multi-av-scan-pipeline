import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { expect, it, vi } from 'vitest'
import BatchJson from './batch-json'

it.each(['status', 'result'])('renders inert batch %s JSON and clears failed refreshes', async kind => {
  const content = '{"filename":"<script>alert(1)</script>"}'
  const fetcher = vi.fn(async () => new Response(JSON.stringify({ batch_id: 2, content })))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient()
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/batches/2']}><Routes>
    <Route path="/batches/:batchId" element={<BatchJson status={kind === 'status'} />} />
  </Routes></MemoryRouter></QueryClientProvider>)
  expect(await screen.findByLabelText(`Batch ${kind} JSON text`)).toHaveTextContent(content)
  expect(document.querySelector('script')).toBeNull()
  expect(fetcher).toHaveBeenCalledWith(`/api/ui/v1/api-ledger/batches/2/json?kind=${kind}`, expect.objectContaining({ cache: 'no-store' }))
  fetcher.mockImplementationOnce(async () => new Response(JSON.stringify({ detail: 'Batch exceeds the limit.' }), { status: 413 }))
  await userEvent.click(screen.getByRole('button', { name: 'Refresh JSON' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Batch exceeds the limit.')
  expect(screen.queryByLabelText(`Batch ${kind} JSON text`)).toBeNull()
  expect(fetcher).toHaveBeenCalledTimes(2)
  // The refusal is not a dead end: the complete contract downloads directly and
  // never enters React state or the query cache.
  expect(screen.getByRole('link', { name: `Download complete ${kind} contract` }))
    .toHaveAttribute('href', `/api/ui/v1/api-ledger/batches/2/download?kind=${kind}`)
  expect(fetcher).toHaveBeenCalledTimes(2)
  view.unmount()
  await vi.waitFor(() => expect(client.getQueryData(['automation-batch-json', '2', kind])).toBeUndefined())
})
