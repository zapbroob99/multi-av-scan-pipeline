import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi } from 'vitest'
import { AutomationExports } from './automation-exports'

describe('Automation exports', () => {
  it('downloads on demand using scoped routes without rendering raw content', async () => {
    const create = vi.fn(() => 'blob:export')
    vi.stubGlobal('URL', { createObjectURL: create, revokeObjectURL: vi.fn() })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ filename: 'masp-scan-42-full.json', media_type: 'application/json', content: '<script>inert</script>' })))
    vi.stubGlobal('fetch', fetcher)
    render(<AutomationExports scanId={42} />)
    expect(fetcher).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Download full JSON' }))
    await waitFor(() => expect(click).toHaveBeenCalledOnce())
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/api-ledger/scans/42/export?format=json', expect.objectContaining({ cache: 'no-store' }))
    expect(create).toHaveBeenCalledOnce()
    expect(screen.queryByText('<script>inert</script>')).toBeNull()
    expect(document.querySelector('script')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Download summary CSV' }))
    expect(fetcher).toHaveBeenCalledWith('/api/ui/v1/api-ledger/scans/42/summary-export?format=csv', expect.anything())
    click.mockRestore()
  })
  it('reports rejection without download, retained output or automatic retries', async () => {
    const create = vi.fn()
    vi.stubGlobal('URL', { createObjectURL: create, revokeObjectURL: vi.fn() })
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ detail: 'Export exceeds 2 MiB' }), { status: 413 }))
    vi.stubGlobal('fetch', fetcher)
    render(<AutomationExports scanId={42} />)
    await userEvent.click(screen.getByRole('button', { name: 'Download full CSV' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('not automatically retried')
    expect(fetcher).toHaveBeenCalledOnce()
    expect(create).not.toHaveBeenCalled()
  })
})
