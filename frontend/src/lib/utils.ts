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

function validTime(value: string | number | null | undefined) {
  const time = recordedTime(value)
  return Number.isFinite(time) && Math.abs(time) <= 8.64e15 ? time : null
}

const pad = (value: number) => String(value).padStart(2, '0')

/** "UTC" at offset zero, otherwise "UTC+3", "UTC-4" or "UTC+05:30". */
function zoneLabel(date: Date) {
  const offset = -date.getTimezoneOffset()
  if (!offset) return 'UTC'
  const minutes = Math.abs(offset), hours = Math.floor(minutes / 60)
  return `UTC${offset > 0 ? '+' : '-'}${minutes % 60 ? `${pad(hours)}:${pad(minutes % 60)}` : hours}`
}

/** Operator timestamps in the browser's time zone, always labelled with their offset so none is ambiguous. */
export function formatTimestamp(value: string | number | null | undefined) {
  const time = validTime(value)
  if (time === null) return 'Not recorded'
  const date = new Date(time)
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} `
    + `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())} ${zoneLabel(date)}`
}

/** The same instant in UTC, as stored; shown on hover beside the local time. */
export function formatUtcTimestamp(value: string | number | null | undefined) {
  const time = validTime(value)
  return time === null ? 'Not recorded' : new Date(time).toISOString().slice(0, 19).replace('T', ' ') + ' UTC'
}

/** ISO 8601 form for a <time> element's dateTime, or null when nothing was recorded. */
export function isoTimestamp(value: string | number | null | undefined) {
  const time = validTime(value)
  return time === null ? null : new Date(time).toISOString()
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
