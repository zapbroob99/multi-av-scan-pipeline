import { afterEach, describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { formatTimestamp, formatUtcTimestamp, heartbeatLabel, sinceRecorded } from './utils'
import { Timestamp } from '../components/timestamp'

describe('Recorded times', () => {
  it('normalizes database UTC, offset timestamps and epoch seconds to the same instant', () => {
    const expected = '2026-09-28 07:00:00 UTC'
    for (const value of ['2026-09-28 07:00:00', '2026-09-28T07:00:00Z', '2026-09-28 07:00:00+00',
      '2026-09-28T10:00:00+03:00', Date.parse('2026-09-28T07:00:00Z') / 1000]) {
      expect(formatTimestamp(value)).toBe(expected)
    }
    expect(sinceRecorded('2026-09-28 07:00:00', Date.parse('2026-09-28T07:01:00Z'))).toBe('60 s')
  })
  it('keeps missing or invalid times separate from a very old recorded heartbeat', () => {
    for (const value of [null, undefined, '', 'invalid', 0, -1, Infinity]) expect(formatTimestamp(value)).toBe('Not recorded')
    expect(heartbeatLabel(0, 1790580124)).toBe('No heartbeat recorded')
    expect(heartbeatLabel(1, 1790580124)).toBe('Last heartbeat 1970-01-01 00:00:01 UTC')
    expect(heartbeatLabel(1790580000, 45)).toBe('Heartbeat 45 s ago')
  })

  describe('in the browser time zone', () => {
    const original = process.env.TZ
    afterEach(() => { process.env.TZ = original })

    it('shows local time with its offset and keeps the stored UTC value for hover', () => {
      process.env.TZ = 'Europe/Istanbul'
      expect(formatTimestamp('2026-09-28 07:00:00')).toBe('2026-09-28 10:00:00 UTC+3')
      expect(formatUtcTimestamp('2026-09-28 07:00:00')).toBe('2026-09-28 07:00:00 UTC')
      render(<Timestamp value="2026-09-28 07:00:00" />)
      const time = screen.getByText('2026-09-28 10:00:00 UTC+3')
      expect(time.tagName).toBe('TIME')
      expect(time).toHaveAttribute('title', '2026-09-28 07:00:00 UTC')
      expect(time).toHaveAttribute('dateTime', '2026-09-28T07:00:00.000Z')
    })

    it('labels negative and fractional offsets and the date change across midnight', () => {
      process.env.TZ = 'America/New_York'
      expect(formatTimestamp('2026-09-28 02:30:00')).toBe('2026-09-27 22:30:00 UTC-4')
      process.env.TZ = 'Asia/Kolkata'
      expect(formatTimestamp('2026-09-28 20:00:00')).toBe('2026-09-29 01:30:00 UTC+05:30')
    })

    it('adds no hover and no element when nothing was recorded or the zone is UTC', () => {
      process.env.TZ = 'UTC'
      render(<Timestamp value="2026-09-28 07:00:00" />)
      expect(screen.getByText('2026-09-28 07:00:00 UTC')).not.toHaveAttribute('title')
      const { container } = render(<Timestamp value={null} />)
      expect(container.textContent).toBe('Not recorded')
      expect(container.querySelector('time')).toBeNull()
    })
  })
})
