import { useEffect, useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { locationPath, type StoragePolicy } from '../lib/storage'
import { ErrorMessage } from '../components/error-message'
import { BackLink } from '../components/section-tabs'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

/** A watched folder: where it is, which client and profile it belongs to, and how often it is read.
 * What happens to each file is the profile's rules, edited on the client's Scan profiles tab. */
export default function StorageLocationForm({ session }: { session: Session }) {
  const locationId = Number(useParams().locationId) || null
  const [params] = useSearchParams()
  const presetClient = locationId ? '' : params.get('client') || ''
  const navigate = useNavigate()
  const client = useQueryClient()
  const options = useQuery({ queryKey: ['storage-options'], queryFn: ({ signal }) => request('/api/ui/v1/storage/options', 'get', { signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false })
  const existing = useQuery({ queryKey: ['storage-location', locationId], enabled: locationId !== null,
    queryFn: ({ signal }) => request('/api/ui/v1/storage/locations/{location_id}', 'get', { params: { location_id: locationId! }, signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false })

  const [name, setName] = useState('')
  const [clientId, setClientId] = useState(presetClient)
  const [profileId, setProfileId] = useState('')
  const [backend, setBackend] = useState('')
  const [prefix, setPrefix] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [ignore, setIgnore] = useState('')
  const [stability, setStability] = useState('60')
  const [interval, setIntervalSeconds] = useState('300')
  const [review, setReview] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    const settings = locationId ? existing.data?.policy : options.data?.default_policy
    if (loaded || !settings || (locationId && existing.data?.policy_invalid)) return
    if (locationId && existing.data) {
      setName(existing.data.name); setClientId(String(existing.data.client.id)); setProfileId(String(existing.data.profile.id))
      setBackend(existing.data.backend_key); setPrefix(existing.data.prefix); setEnabled(existing.data.enabled)
    }
    setIgnore((settings.ignore_patterns ?? []).join('\n'))
    setStability(String(settings.stability_seconds ?? 60)); setIntervalSeconds(String(settings.crawl_interval_seconds ?? 300))
    setLoaded(true)
  }, [existing.data, options.data, locationId, loaded])

  const chosenClient = options.data?.clients.find(item => String(item.id) === clientId)
  const chosenProfile = chosenClient?.profiles.find(item => String(item.id) === profileId)
  const baseSettings = (locationId ? existing.data?.policy : options.data?.default_policy) ?? {}
  const back = locationId ? `/storage/locations/${locationId}` : presetClient ? `/service-clients/${presetClient}/storage` : '/storage'

  function settings(): StoragePolicy {
    return { ...baseSettings, ignore_patterns: ignore.split('\n').map(item => item.trim()).filter(Boolean),
      stability_seconds: Number(stability), crawl_interval_seconds: Number(interval) }
  }
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError('')
    if (!name.trim() || !clientId || !profileId || !backend) { setError('Name, client, profile and backend are required.'); return }
    if (![stability, interval].every(value => Number.isInteger(Number(value)) && Number(value) > 0)) {
      setError('Settle time and crawl interval must be whole numbers of seconds.'); return
    }
    setReview(true)
  }
  async function save() {
    setBusy(true); setError('')
    try {
      // No automatic retry: an uncertain outcome is resolved by reading the folder again.
      if (locationId && existing.data) {
        await request('/api/ui/v1/storage/locations/{location_id}', 'put', { params: { location_id: locationId }, csrf: session.csrf_token,
          body: { expected_management_revision: existing.data.management_revision, name: name.trim(), scan_profile_id: Number(profileId), enabled, policy: settings() } })
        await client.invalidateQueries({ queryKey: ['storage-location', locationId] })
        navigate(`/storage/locations/${locationId}`)
      } else {
        const created = await request('/api/ui/v1/storage/locations', 'post', { csrf: session.csrf_token,
          body: { name: name.trim(), service_client_id: Number(clientId), scan_profile_id: Number(profileId), backend_key: backend,
            prefix: prefix.trim(), mode: 'crawl', enabled, policy: settings() } })
        await client.invalidateQueries({ queryKey: ['storage-presence'] })
        navigate(`/storage/locations/${created.id}`)
      }
    } catch (e) { setError(`${(e as Error).message} Nothing is retried automatically; reopen the folder to see what was stored.`) }
    finally { setBusy(false); setReview(false) }
  }

  if (session.user.role !== 'admin') return <section className="empty"><h1>Administrator access required</h1></section>
  const pending = options.isPending || (locationId !== null && existing.isPending)
  const loadError = options.error || existing.error
  return <section className="page management-page">
    <div className="page-heading"><div><p className="eyebrow">FOLDER SCANNING</p><h1>{locationId ? 'Edit watched folder' : 'Watch a folder'}</h1>
      <p className="muted">{locationId && existing.data ? <code>{locationPath(existing.data)}</code> : 'A folder MASP reads itself, judging each file by the client’s profile rules.'}</p></div>
      <BackLink to={back} /></div>
    {pending && <p role="status">Loading…</p>}
    {loadError && <p role="alert" className="error"><ErrorMessage message={loadError.message || ''} /></p>}
    {locationId && existing.data?.policy_invalid && <p className="notice error" role="alert">The stored folder settings could not be read, so they
      cannot be edited here without silently replacing them with defaults. Correct them in the database or recreate the folder.</p>}
    {!pending && !loadError && options.data && loaded && <form onSubmit={prepare} className="submission-card" aria-label="Folder settings">
      <h2>Folder</h2>
      <label>Name<input value={name} maxLength={128} required onChange={e => setName(e.target.value)} /></label>
      <label>Service client<select value={clientId} required disabled={locationId !== null || Boolean(presetClient)} onChange={e => { setClientId(e.target.value); setProfileId('') }}>
        <option value="">Select a client</option>{options.data.clients.map(item => <option key={item.id} value={item.id} disabled={!item.enabled}>
          {item.name} ({item.client_key}){item.enabled ? '' : ' · disabled'}</option>)}</select></label>
      <label>Scan profile<select value={profileId} required onChange={e => setProfileId(e.target.value)}>
        <option value="">Select a profile</option>{chosenClient?.profiles.map(item => <option key={item.id} value={item.id} disabled={!item.enabled}>
          {item.name}{item.enabled ? '' : ' · disabled'}</option>)}</select></label>
      <p className="muted">Every file in the folder takes the first rule of this profile it matches, like a file the client sends.
        Light check and Block are applied while the folder is read; a file a Scan rule matches waits until antivirus scanning of folders is available.
        {chosenClient && <> Edit the rules on <Link to={`/service-clients/${chosenClient.id}/profiles`}>{chosenClient.name}'s Scan profiles</Link>.</>}</p>
      <label>Storage backend<select value={backend} required disabled={locationId !== null} onChange={e => setBackend(e.target.value)}>
        <option value="">Select a backend</option>{options.data.backends.map(key => <option key={key} value={key}>{key}</option>)}</select></label>
      {!options.data.backends.length && <p className="notice error" role="alert">No storage backend is configured on this deployment. Backends are
        deployment settings (MASP_DEFERRED_STORAGE_BACKENDS_JSON); the console never accepts a filesystem path.</p>}
      <label>Folder inside the backend<input value={prefix} maxLength={512} disabled={locationId !== null} placeholder="uploads/finance"
        onChange={e => setPrefix(e.target.value)} /></label>
      <p className="muted">The client's storage access must cover this folder, and watched folders on one backend must not overlap. Client, backend and
        folder cannot change later: the inventory describes exactly this tree.</p>
      <label className="check-row"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} /> Enabled</label>

      <h2>Reading</h2>
      <label>Ignored names (one pattern per line)<textarea rows={4} value={ignore} spellCheck={false} onChange={e => setIgnore(e.target.value)} /></label>
      <label>Settle time (seconds without change before inspection)<input value={stability} inputMode="numeric" onChange={e => setStability(e.target.value)} /></label>
      <label>Crawl interval (seconds between complete crawls)<input value={interval} inputMode="numeric" onChange={e => setIntervalSeconds(e.target.value)} /></label>
      {error && <p role="alert" className="error"><ErrorMessage message={error} /></p>}
      <Button type="submit" disabled={busy || Boolean(locationId && existing.data?.policy_invalid)}>Review</Button>
    </form>}
    <Dialog open={review} locked={busy} onOpenChange={open => { if (!open && !busy) setReview(false) }}
      title={locationId ? 'Save this folder?' : 'Watch this folder?'}
      description={locationId ? 'Changes apply to files inspected afterwards; files already inspected are judged again only when they change.'
        : 'The storage protection worker starts reading it on its next sweep if the backend is mounted there.'}>
      <p><strong>{name.trim()}</strong> · {backend}:/{prefix.trim()}</p>
      <p>Rules of {chosenProfile?.name ?? 'the selected profile'} · settles after {stability} s · crawled every {interval} s{enabled ? '' : ' · disabled'}</p>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => setReview(false)}>Cancel</Button>
        <Button disabled={busy} onClick={() => { void save() }}>{busy ? 'Saving…' : 'Confirm'}</Button></div>
    </Dialog>
  </section>
}
