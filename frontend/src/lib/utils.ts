import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
export function cn(...values: ClassValue[]) { return twMerge(clsx(values)) }

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
  const text = value.includes('T') ? value : value.replace(' ', 'T')
  const zoned = /([zZ]|[+-]\d\d:?\d\d)$/.test(text) ? text : `${text}Z`
  const time = Date.parse(zoned)
  return Number.isNaN(time) ? null : shortAge((now - time) / 1000)
}
