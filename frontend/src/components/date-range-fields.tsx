import { currentZoneLabel } from '../lib/utils'

/** "From" and "To" days for a history list's filter form. Both days are
 * included and read in the browser's time zone, the same zone the list shows
 * its times in; `withDateWindow` turns them into the API's instants. */
export function DateRangeFields({ params, idPrefix }: { params: URLSearchParams; idPrefix: string }) {
  const help = `${idPrefix}-date-help`
  return <>
    <label>From<input type="date" name="from" defaultValue={params.get('from') || ''} min="2000-01-01" max="9999-12-31" aria-describedby={help} /></label>
    <label>To<input type="date" name="to" defaultValue={params.get('to') || ''} min="2000-01-01" max="9999-12-31" aria-describedby={help} /></label>
    <small id={help} className="muted date-range-help">Whole days in your time zone ({currentZoneLabel()}), both included.</small>
  </>
}
