import { describe, expect, it } from 'vitest'
import { formatTimestamp, heartbeatLabel, sinceRecorded } from './utils'

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
})
