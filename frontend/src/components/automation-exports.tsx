import { useState } from 'react'
import { request } from '../lib/api'
import { Button } from './ui/button'

export function AutomationExports({ scanId, disabled = false }: { scanId: number; disabled?: boolean }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function download(scope: 'summary' | 'full', format: 'json' | 'csv') {
    if (busy || disabled) return
    setBusy(true); setError('')
    try {
      const exported = await request(scope === 'full' ? '/api/ui/v1/api-ledger/scans/{scan_id}/export' : '/api/ui/v1/api-ledger/scans/{scan_id}/summary-export', 'get', {
        params: { scan_id: scanId }, query: new URLSearchParams({ format }) })
      const url = URL.createObjectURL(new Blob([exported.content], { type: `${exported.media_type};charset=utf-8` }))
      const anchor = document.createElement('a')
      try {
        anchor.href = url; anchor.download = exported.filename; document.body.append(anchor); anchor.click()
      } finally { anchor.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 1000) }
    } catch (e) { setError((e as Error).message) } finally { setBusy(false) }
  }
  return <section className="submission-card"><h2>Export automation report</h2>
    <p>Summary exports include bounded report text, backend decisions and coverage, without raw output or archive children.
      Full JSON includes engine output, details and findings; full CSV contains normalized report rows.
      These operator reports are not the integration API status/result JSON contract.</p>
    <p>Exports use fresh backend reads with a 2 MiB limit. Stored sample paths and sample bytes are excluded.
      A full export is unavailable for historical automation scans without a routing snapshot or engine jobs.</p>
    <div className="report-actions">{(['summary', 'full'] as const).flatMap(scope => (['json', 'csv'] as const).map(format =>
      <Button key={`${scope}-${format}`} variant="secondary" disabled={busy || disabled} onClick={() => { void download(scope, format) }}>
        Download {scope} {format.toUpperCase()}</Button>))}</div>
    {busy && <p role="status">Preparing export…</p>}
    {error && <p role="alert" className="error">{error} Downloads are not automatically retried.</p>}
  </section>
}
