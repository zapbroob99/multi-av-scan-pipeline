import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { ErrorMessage } from './error-message'

describe('Error reference', () => {
  it('copies only the request ID and renders server details as inert text', async () => {
    const user = userEvent.setup()
    const write = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue()
    render(<p role="alert"><ErrorMessage message="<script>details</script> [Request ID: trace/42]" /></p>)
    expect(document.querySelector('script')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Copy request ID' }))
    expect(write).toHaveBeenCalledWith('trace/42')
    expect(screen.getByRole('button', { name: 'Request ID copied' })).toBeVisible()
  })
  it('leaves the reference selectable when clipboard access is unavailable', async () => {
    const user = userEvent.setup()
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('Denied'))
    render(<ErrorMessage message="Failed [Request ID: trace-1]" />)
    await user.click(screen.getByRole('button', { name: 'Copy request ID' }))
    expect(screen.getByText(/Select the request ID/)).toBeVisible()
  })
})
