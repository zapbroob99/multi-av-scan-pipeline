import { render } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { RiskBadge } from './risk-badge'

function badge(props: Parameters<typeof RiskBadge>[0]) {
  const { container } = render(<RiskBadge {...props} />)
  return container.querySelector('.risk-badge')!
}

describe('RiskBadge', () => {
  it('shows a quiet "No detection" instead of an orange low score for a clean scan', () => {
    const clean = badge({ level: 'info', score: 0 })
    expect(clean).toHaveTextContent('No detection')
    expect(clean).toHaveClass('risk-badge-clear')
    expect(clean).not.toHaveTextContent('/ 100')
  })

  it('treats the legacy "low / 10" clean score the same way', () => {
    expect(badge({ level: 'low', score: 10 })).toHaveClass('risk-badge-clear')
  })

  it('says a scan is incomplete when engines failed or were skipped', () => {
    const partial = badge({ level: 'info', score: 0, unavailable: 2 })
    expect(partial).toHaveTextContent('Incomplete')
    expect(partial).toHaveTextContent('2 engines did not run')
    expect(partial).toHaveClass('risk-badge-review')
  })

  it('keeps detections red even when other engines did not run', () => {
    const detected = badge({ level: 'high', score: 70, unavailable: 1 })
    expect(detected).toHaveClass('risk-badge-alert')
    expect(detected).toHaveTextContent('High')
    expect(detected).toHaveTextContent('70 / 100')
  })

  it('does not score active or unscored scans', () => {
    expect(badge({ level: 'pending', score: null, pending: true })).toHaveTextContent('Pending')
    expect(badge({ level: 'info', score: null })).toHaveTextContent('Not scored')
    expect(badge({ level: 'info', score: 0, failed: true })).toHaveTextContent('Not scored')
  })
})
