import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
export function cn(...values: ClassValue[]) { return twMerge(clsx(values)) }

/** Database timestamps without an offset are UTC, never browser-local time. */
function recordedTime(value: string | number | null | undefined) {
  if (value === null || value === undefined || value === '') return NaN
  if (typeof value === 'number') return value > 0 ? value * 1000 : NaN
  let text = value.includes('T') ? value : value.replace(' ', 'T')
  // PostgreSQL may spell a whole-hour offset as +00 rather than +00:00.
  if (text.includes('T') && /[+-]\d\d$/.test(text)) text += ':00'
  return Date.parse(/([zZ]|[+-]\d\d:?\d\d)$/.test(text) ? text : `${text}Z`)
}

/** One explicit timezone and format for operator timestamps across the console. */
export function formatTimestamp(value: string | number | null | undefined) {
  const time = recordedTime(value)
  if (!Number.isFinite(time) || Math.abs(time) > 8.64e15) return 'Not recorded'
  return new Date(time).toISOString().slice(0, 19).replace('T', ' ') + ' UTC'
}

export function heartbeatLabel(timestamp: number | null | undefined, age: number) {
  if (!timestamp || !Number.isFinite(timestamp) || timestamp < 0) return 'No heartbeat recorded'
  if (!Number.isFinite(age) || age >= 48 * 3600) return `Last heartbeat ${formatTimestamp(timestamp)}`
  return `Heartbeat ${shortAge(age)} ago`
}

/** Compact age for list rows: "45 s", "12 min", "3 h", "5 d". */
export function shortAge(seconds: number) {
  if (seconds < 90) return `${Math.max(0, Math.round(seconds))} s`
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)} min`
  if (seconds < 48 * 3600) return `${Math.round(seconds / 3600)} h`
  return `${Math.round(seconds / 86400)} d`
}

/** Age of a recorded timestamp (ISO or "YYYY-MM-DD HH:MM:SS", UTC when unzoned). */
export function sinceRecorded(value: string | null | undefined, now = Date.now()) {
  if (!value) return null
  const time = recordedTime(value)
  return Number.isNaN(time) ? null : shortAge((now - time) / 1000)
}
