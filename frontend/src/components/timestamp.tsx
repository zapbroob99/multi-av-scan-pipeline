import { formatTimestamp, formatUtcTimestamp, isoTimestamp } from '../lib/utils'

/** A recorded time in the browser's time zone; hovering shows the stored UTC value. */
export function Timestamp({ value }: { value: string | number | null | undefined }) {
  const iso = isoTimestamp(value)
  const local = formatTimestamp(value), utc = formatUtcTimestamp(value)
  if (iso === null) return <>{local}</>
  return <time dateTime={iso} title={local === utc ? undefined : utc}>{local}</time>
}
