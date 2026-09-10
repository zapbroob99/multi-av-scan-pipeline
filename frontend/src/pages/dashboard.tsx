import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowDown, ArrowUpRight, RefreshCw, Search } from 'lucide-react'
import type { FormEvent } from 'react'
import { request, type ScanPreview } from '../lib/api'
import { Button } from '../components/ui/button'

export function historyPollInterval(before: string) { return before ? false : 20000 }

function displayTime(value: string) {
  // SQLite's CURRENT_TIMESTAMP is UTC without a suffix; PostgreSQL includes it.
  const iso = value.replace(' ', 'T')
  const date = new Date(/(?:Z|[+-]\d\d(?::?\d\d)?)$/.test(iso) ? iso : iso + 'Z')
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function riskText(scan: ScanPreview) {
  if (['queued', 'running', 'finalizing'].includes(scan.status)) return 'Pending'
  if (scan.risk_score === null) return 'Not scored'
  return `${scan.risk_score} / 100 · ${scan.risk_level}`
}

export default function Dashboard() {
  const [params, setParams] = useSearchParams()
  const q = params.get('q') || '', status = params.get('status') || 'all', risk = params.get('risk') || 'all'
  const before = params.get('before') || ''
  const query = new URLSearchParams({ q, status, risk, limit: '20', ...(before ? { before } : {}) }).toString()
  const summary = useQuery({ queryKey: ['dashboard', 'summary'],
    queryFn: ({ signal }) => request('/api/ui/v1/dashboard/summary', 'get', { signal }),
    refetchInterval: 30000, refetchIntervalInBackground: false })
  const scans = useQuery({ queryKey: ['dashboard', 'scans', query],
    queryFn: ({ signal }) => request('/api/ui/v1/dashboard/scans', 'get', { query: new URLSearchParams(query), signal }),
    refetchInterval: historyPollInterval(before), refetchIntervalInBackground: false, gcTime: 60000 })
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget), next = new URLSearchParams()
    for (const key of ['q', 'status', 'risk']) {
      const value = String(form.get(key) || '').trim()
      if (value && value !== 'all') next.set(key, value)
    }
    setParams(next)
  }
  function latest() { const next = new URLSearchParams(params); next.delete('before'); setParams(next) }
  const isBusy = scans.isFetching || summary.isFetching
  return <section className="page dashboard-page">
    <div className="page-heading"><div><p className="eyebrow">MANUAL SCAN ACTIVITY</p><h1>Dashboard</h1>
      <p className="muted">Recent submissions, processing state and recorded risk.</p></div>
      <Link className="button button-primary" to="/scans/new"><ArrowUpRight size={16} />Submit sample</Link></div>
    {summary.error && <p role="alert" className="error">Summary unavailable: {summary.error.message}</p>}
    <div className="stats-row dashboard-stats" aria-label="Manual scan summary">
      <div><span>Samples</span><strong>{summary.data?.total.toLocaleString() ?? '—'}</strong></div>
      <div><span>Active scans</span><strong>{summary.data?.active.toLocaleString() ?? '—'}</strong></div>
      <div><span>High risk</span><strong>{summary.data?.high_risk.toLocaleString() ?? '—'}</strong></div>
      <div><span>Enabled engines</span><strong>{summary.data?.enabled_engines.toLocaleString() ?? '—'}</strong></div>
    </div>
    <div className="history-heading"><div><h2>Scan history</h2><p className="muted">Manual submissions only; archive children and API/ICAP scans are excluded.</p></div>
      <Button variant="secondary" disabled={isBusy} onClick={() => { void scans.refetch(); void summary.refetch() }}>
        <RefreshCw size={14} />{isBusy ? 'Refreshing…' : 'Refresh'}</Button></div>
    <form key={params.toString()} className="history-filters" onSubmit={filter} aria-label="Scan filters">
      <label className="search"><Search size={16} /><input name="q" aria-label="Search scans" maxLength={200}
        defaultValue={q} placeholder="Filename, hash or case…" /></label>
      <label>Status<select name="status" defaultValue={status}>
        {['all', 'active', 'queued', 'running', 'finalizing', 'completed', 'partial', 'failed'].map(value =>
          <option key={value} value={value}>{value === 'all' ? 'All statuses' : value}</option>)}
      </select></label>
      <label>Recorded risk<select name="risk" defaultValue={risk}>
        {['all', 'pending', 'info', 'low', 'medium', 'high', 'critical'].map(value =>
          <option key={value} value={value}>{value === 'all' ? 'All risk levels' : value}</option>)}
      </select></label>
      <Button variant="secondary">Apply filters</Button>
      <Button type="button" variant="secondary" onClick={() => setParams({})}>Reset</Button>
    </form>
    <p className="callout">Risk is not a clean verdict. A completed scan may have missing engines. Open a report for detection coverage and the policy decision.</p>
    {scans.error && <p role="alert" className="error">History unavailable: {scans.error.message} Use Refresh to retry.</p>}
    {scans.isPending ? <div role="status" className="skeleton">Loading scan history…</div> : scans.data && <>
      {scans.data.items.length === 0 ? <div className="empty"><h2>No scans found</h2><p>Change the filters or return to the latest submissions.</p></div> :
        <div className="history-table-wrap" tabIndex={0} role="region" aria-label="Scan history table"><table className="history-table">
          <thead><tr><th scope="col">Sample</th><th scope="col">Status</th><th scope="col">Recorded risk</th><th scope="col">Submitted</th></tr></thead>
          <tbody>{scans.data.items.map(scan => <tr key={scan.id}>
            <td><Link className="sample-link" to={`/scans/${scan.id}`}>{scan.filename}</Link>
              <small className="sample-hash" title={scan.sha256}>{scan.sha256}</small>
              <small>#{scan.id} · {(scan.size_bytes / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} KB{scan.case_name ? ` · ${scan.case_name}` : ''}</small></td>
            <td><span className={`health-pill ${scan.status === 'failed' ? 'health-failed' : ''}`}>{scan.status}</span></td>
            <td className={['high', 'critical'].includes(scan.risk_level) ? 'risk-high' : ''}>{riskText(scan)}</td>
            <td><time dateTime={scan.created_at}>{displayTime(scan.created_at)}</time></td>
          </tr>)}</tbody></table></div>}
      <div className="history-pagination"><p className="muted">{scans.data.items.length} shown · Newest submission ID first{before ? ' · History page (auto-refresh paused)' : ''}</p>
        <div>{before && <Button variant="secondary" onClick={latest}>Latest scans</Button>}
          <Button variant="secondary" disabled={!scans.data.next_before || scans.isFetching} onClick={() => {
            const next = new URLSearchParams(params); next.set('before', String(scans.data!.next_before)); setParams(next)
          }}>Older scans<ArrowDown size={14} /></Button></div></div>
    </>}
    <p className="muted history-footnote">Summary covers all manual history. Refresh: 30 seconds; server cache: up to 30 seconds.
      {summary.data && <> Updated {displayTime(summary.data.generated_at)}.</>} Enabled does not mean healthy.
      {' '}<a href="/">Legacy Dashboard &amp; bulk actions</a></p>
  </section>
}
