import { useState, type FormEvent } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { Button } from '../components/ui/button'

export default function HashScan({ session }: { session: Session }) {
  const [sha256, setSha256] = useState('')
  const options = useQuery({ queryKey: ['hash-options'], queryFn: ({ signal }) => request('/api/ui/v1/hash-scan/options', 'get', { signal }),
    retry: false, gcTime: 0, refetchOnWindowFocus: false, refetchOnReconnect: false })
  const lookup = useMutation({ retry: false, gcTime: 0, mutationFn: (hash: string) => request('/api/ui/v1/hash-scan', 'post', {
    csrf: session.csrf_token, body: { sha256: hash } }) })
  function submit(event: FormEvent) { event.preventDefault(); if (!lookup.isPending) lookup.mutate(sha256.trim()) }
  return <section className="page management-page"><div className="page-heading"><div><p className="eyebrow">MANUAL LOOKUP</p><h1>Hash lookup</h1>
    <p className="muted">Check SHA-256 reputation without uploading file contents.</p></div></div>
    <p className="callout">Submitting sends the hash to enabled reputation providers and may consume external quota. Reputation is not a file scan or proof of complete detection coverage.
      No automatic retry, polling or scan-history record is created.</p>
    {options.isPending && <p role="status">Loading hash engines…</p>}
    {options.error && <p role="alert" className="error">{options.error.message}</p>}
    {options.data && <p className="muted report-filename">{options.data.engines.length ? `Enabled hash engines: ${options.data.engines.map(e => e.name).join(', ')}` : 'No hash-capable engine is added and enabled in MASP.'}</p>}
    <Button variant="secondary" disabled={options.isFetching || lookup.isPending} onClick={() => { void options.refetch() }}>Refresh engines</Button>
    <form className="submission-card" onSubmit={submit}><label htmlFor="lookup-sha256">SHA-256</label>
      <input id="lookup-sha256" required minLength={64} maxLength={64} pattern="[0-9a-fA-F]{64}" autoComplete="off" spellCheck={false}
        value={sha256} disabled={lookup.isPending} onChange={event => { setSha256(event.target.value); lookup.reset() }} />
      <Button disabled={lookup.isPending || options.isFetching || !!options.error || !options.data?.engines.length}>
        {lookup.isPending ? 'Looking up…' : 'Look up hash'}</Button></form>
    {lookup.error && <p role="alert" className="error">{lookup.error.message} The request may have reached a provider and consumed quota. No complete decision is available. Retry only as an explicit new lookup.</p>}
    {lookup.data && !lookup.error && !lookup.isPending && <section className="submission-card" aria-label="Hash lookup result">
      <h2>Reputation decision: {lookup.data.action}</h2><p className="sample-hash">{lookup.data.sha256}</p><p>{lookup.data.reason}</p>
      {lookup.data.results.map(row => <article className="report-engine" key={row.id}><h3>{row.name}</h3><p>Decision: {row.action} · {row.found ? 'Hash found' : 'Hash not found'}</p></article>)}
      <p className="muted">This decision applies only to this reputation lookup. A missing hash does not establish that the file is clean.</p>
    </section>}
  </section>
}
