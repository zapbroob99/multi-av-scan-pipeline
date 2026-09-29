import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { request, type Session } from '../lib/api'
import { FAMILY_LABELS, locationPath, type StoragePolicy } from '../lib/storage'
import { ErrorMessage } from '../components/error-message'
import { BackLink } from '../components/section-tabs'
import { Button } from '../components/ui/button'
import { Dialog } from '../components/ui/dialog'

const GIB = 1024 ** 3
type Rule = { pattern: string; min: string; max: string; tier: 'full' | 'light' }

/** Tier rule sizes are entered in MiB; blank means no bound. */
export function rulesToPolicy(rules: Rule[]) {
  const size = (value: string) => value.trim() === '' ? null : Math.round(Number(value) * 1024 * 1024)
  return rules.filter(rule => rule.pattern.trim()).map(rule => ({
    pattern: rule.pattern.trim(), min_bytes: size(rule.min), max_bytes: size(rule.max), tier: rule.tier }))
}

function rulesFromPolicy(policy: StoragePolicy): Rule[] {
  const mib = (value: number | null | undefined) => value == null ? '' : String(value / (1024 * 1024))
  return (policy.tier_rules ?? []).map(rule => ({ pattern: rule.pattern ?? '*', min: mib(rule.min_bytes), max: mib(rule.max_bytes), tier: rule.tier }))
}

export default function StorageLocationForm({ session }: { session: Session }) {
  const locationId = Number(useParams().locationId) || null
  const navigate = useNavigate()
  const client = useQueryClient()
  const options = useQuery({ queryKey: ['storage-options'], queryFn: ({ signal }) => request('/api/ui/v1/storage/options', 'get', { signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false })
  const existing = useQuery({ queryKey: ['storage-location', locationId], enabled: locationId !== null,
    queryFn: ({ signal }) => request('/api/ui/v1/storage/locations/{location_id}', 'get', { params: { location_id: locationId! }, signal }),
    retry: false, staleTime: 0, gcTime: 0, refetchOnMount: 'always', refetchOnWindowFocus: false })

  const [name, setName] = useState('')
  const [clientId, setClientId] = useState('')
  const [profileId, setProfileId] = useState('')
  const [backend, setBackend] = useState('')
  const [prefix, setPrefix] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [defaultTier, setDefaultTier] = useState<'full' | 'light'>('light')
  const [rules, setRules] = useState<Rule[]>([])
  const [typeMode, setTypeMode] = useState<'allowlist' | 'denylist'>('denylist')
  const [families, setFamilies] = useState<string[]>(['executable', 'script'])
  const [archiveAction, setArchiveAction] = useState<'full' | 'allow' | 'detect'>('full')
  const [hashEnabled, setHashEnabled] = useState(true)
  const [hashMaxGib, setHashMaxGib] = useState('10')
  const [ignore, setIgnore] = useState('')
  const [stability, setStability] = useState('60')
  const [interval, setIntervalSeconds] = useState('300')
  const [review, setReview] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    const policy = locationId ? existing.data?.policy : options.data?.default_policy
    if (loaded || !policy || (locationId && existing.data?.policy_invalid)) return
    if (locationId && existing.data) {
      setName(existing.data.name); setClientId(String(existing.data.client.id)); setProfileId(String(existing.data.profile.id))
      setBackend(existing.data.backend_key); setPrefix(existing.data.prefix); setEnabled(existing.data.enabled)
    }
    setDefaultTier(locationId ? policy.default_tier ?? 'full' : 'light')
    setRules(rulesFromPolicy(policy))
    setTypeMode(policy.type_policy?.mode ?? 'denylist'); setFamilies(policy.type_policy?.families ?? [])
    setArchiveAction(policy.archive_action ?? 'full')
    setHashEnabled(policy.hash_check?.enabled ?? true); setHashMaxGib(String((policy.hash_check?.max_bytes ?? 10 * GIB) / GIB))
    setIgnore((policy.ignore_patterns ?? []).join('\n'))
    setStability(String(policy.stability_seconds ?? 60)); setIntervalSeconds(String(policy.crawl_interval_seconds ?? 300))
    setLoaded(true)
  }, [existing.data, options.data, locationId, loaded])

  const chosenClient = options.data?.clients.find(item => String(item.id) === clientId)
  const basePolicy = (locationId ? existing.data?.policy : options.data?.default_policy) ?? {}

  function policy(): StoragePolicy {
    return { ...basePolicy, default_tier: defaultTier, tier_rules: rulesToPolicy(rules),
      type_policy: { mode: typeMode, families }, archive_action: archiveAction,
      hash_check: { enabled: hashEnabled, max_bytes: Math.round(Number(hashMaxGib || '0') * GIB) },
      ignore_patterns: ignore.split('\n').map(item => item.trim()).filter(Boolean),
      stability_seconds: Number(stability), crawl_interval_seconds: Number(interval) }
  }
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError('')
    if (!name.trim() || !clientId || !profileId || !backend) { setError('Name, client, profile and backend are required.'); return }
    if (typeMode === 'allowlist' && !families.length) { setError('An allowlist with no families would flag every file. Choose at least one family.'); return }
    if (rules.some(rule => [rule.min, rule.max].some(value => value.trim() !== '' && !(Number(value) >= 0)))) {
      setError('Tier rule sizes must be positive numbers of MiB, or blank.'); return
    }
    setReview(true)
  }
  async function save() {
    setBusy(true); setError('')
    try {
      // No automatic retry: an uncertain outcome is resolved by reading the location again.
      if (locationId && existing.data) {
        await request('/api/ui/v1/storage/locations/{location_id}', 'put', { params: { location_id: locationId }, csrf: session.csrf_token,
          body: { expected_management_revision: existing.data.management_revision, name: name.trim(), scan_profile_id: Number(profileId), enabled, policy: policy() } })
        await client.invalidateQueries({ queryKey: ['storage-location', locationId] })
        navigate(`/storage/locations/${locationId}`)
      } else {
        const created = await request('/api/ui/v1/storage/locations', 'post', { csrf: session.csrf_token,
          body: { name: name.trim(), service_client_id: Number(clientId), scan_profile_id: Number(profileId), backend_key: backend,
            prefix: prefix.trim(), mode: 'crawl', enabled, policy: policy() } })
        navigate(`/storage/locations/${created.id}`)
      }
    } catch (e) { setError(`${(e as Error).message} Nothing is retried automatically; reopen the location to see what was stored.`) }
    finally { setBusy(false); setReview(false) }
  }
  function updateRule(index: number, change: Partial<Rule>) { setRules(rules.map((rule, position) => position === index ? { ...rule, ...change } : rule)) }

  if (session.user.role !== 'admin') return <section className="empty"><h1>Administrator access required</h1></section>
  const pending = options.isPending || (locationId !== null && existing.isPending)
  const loadError = options.error || existing.error
  return <section className="page management-page">
    <div className="page-heading"><div><p className="eyebrow">FOLDER SCANNING</p><h1>{locationId ? 'Edit location' : 'New location'}</h1>
      <p className="muted">{locationId && existing.data ? <code>{locationPath(existing.data)}</code> : 'A storage tree MASP will crawl and inspect itself.'}</p></div>
      <BackLink to={locationId ? `/storage/locations/${locationId}` : '/storage'} /></div>
    {pending && <p role="status">Loading…</p>}
    {loadError && <p role="alert" className="error"><ErrorMessage message={loadError.message || ''} /></p>}
    {locationId && existing.data?.policy_invalid && <p className="notice error" role="alert">The stored policy could not be read, so it cannot be
      edited here without silently replacing it with defaults. Correct it in the database or recreate the location.</p>}
    {!pending && !loadError && options.data && loaded && <form onSubmit={prepare} className="submission-card" aria-label="Location settings">
      <h2>Location</h2>
      <label>Name<input value={name} maxLength={128} required onChange={e => setName(e.target.value)} /></label>
      <label>Service client<select value={clientId} required disabled={locationId !== null} onChange={e => { setClientId(e.target.value); setProfileId('') }}>
        <option value="">Select a client</option>{options.data.clients.map(item => <option key={item.id} value={item.id} disabled={!item.enabled}>
          {item.name} ({item.client_key}){item.enabled ? '' : ' · disabled'}</option>)}</select></label>
      <label>Scan profile<select value={profileId} required onChange={e => setProfileId(e.target.value)}>
        <option value="">Select a profile</option>{chosenClient?.profiles.map(item => <option key={item.id} value={item.id} disabled={!item.enabled}>
          {item.name}{item.enabled ? '' : ' · disabled'}</option>)}</select></label>
      <label>Storage backend<select value={backend} required disabled={locationId !== null} onChange={e => setBackend(e.target.value)}>
        <option value="">Select a backend</option>{options.data.backends.map(key => <option key={key} value={key}>{key}</option>)}</select></label>
      {!options.data.backends.length && <p className="notice error" role="alert">No storage backend is configured on this deployment. Backends are
        deployment settings (MASP_DEFERRED_STORAGE_BACKENDS_JSON); the console never accepts a filesystem path.</p>}
      <label>Prefix inside the backend<input value={prefix} maxLength={512} disabled={locationId !== null} placeholder="uploads/finance"
        onChange={e => setPrefix(e.target.value)} /></label>
      <p className="muted">The client's storage grant must cover this prefix, and locations on one backend must not overlap. Client, backend and
        prefix cannot change later: the inventory describes exactly this tree.</p>
      <label className="check-row"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} /> Enabled</label>

      <h2>Tiers</h2>
      <label>Default tier<select value={defaultTier} onChange={e => setDefaultTier(e.target.value as 'full' | 'light')}>
        <option value="light">Light: type policy and hash list, no antivirus</option>
        <option value="full">Full: antivirus scan (not available yet; files wait)</option></select></label>
      <fieldset><legend>Tier rules (first match wins; sizes in MiB, blank for no bound; pattern matches the path under the prefix)</legend>
        {rules.map((rule, index) => <div key={index} className="history-filters">
          <label>Pattern<input value={rule.pattern} maxLength={256} onChange={e => updateRule(index, { pattern: e.target.value })} /></label>
          <label>From MiB<input value={rule.min} inputMode="decimal" onChange={e => updateRule(index, { min: e.target.value })} /></label>
          <label>Up to MiB<input value={rule.max} inputMode="decimal" onChange={e => updateRule(index, { max: e.target.value })} /></label>
          <label>Tier<select value={rule.tier} onChange={e => updateRule(index, { tier: e.target.value as 'full' | 'light' })}>
            <option value="light">light</option><option value="full">full</option></select></label>
          <Button type="button" variant="secondary" aria-label={`Remove rule ${index + 1}`} onClick={() => setRules(rules.filter((_, position) => position !== index))}>Remove</Button>
        </div>)}
        <Button type="button" variant="secondary" disabled={rules.length >= 50} onClick={() => setRules([...rules, { pattern: '*', min: '', max: '', tier: 'light' }])}>Add rule</Button>
      </fieldset>

      <h2>Light tier</h2>
      <label>Type policy<select value={typeMode} onChange={e => setTypeMode(e.target.value as 'allowlist' | 'denylist')}>
        <option value="denylist">Denylist: the families below must not appear</option>
        <option value="allowlist">Allowlist: only the families below may appear</option></select></label>
      <fieldset className="check-grid"><legend>Content families</legend>
        {options.data.families.map(family => <label key={family} className="check-row"><input type="checkbox" checked={families.includes(family)}
          onChange={e => setFamilies(e.target.checked ? [...families, family] : families.filter(item => item !== family))} /> {FAMILY_LABELS[family] ?? family}</label>)}
      </fieldset>
      <p className="muted">Scripts have no reliable magic bytes: they are recognized by extension and by a <code>#!</code> header only.</p>
      <label>Archives<select value={archiveAction} onChange={e => setArchiveAction(e.target.value as 'full' | 'allow' | 'detect')}>
        <option value="full">Send to the full tier (a header cannot show what an archive holds)</option>
        <option value="allow">Allow</option><option value="detect">Detect</option></select></label>
      <label className="check-row"><input type="checkbox" checked={hashEnabled} onChange={e => setHashEnabled(e.target.checked)} /> Check SHA-256 against the hash list</label>
      <label>Hash files up to (GiB)<input value={hashMaxGib} inputMode="decimal" disabled={!hashEnabled} onChange={e => setHashMaxGib(e.target.value)} /></label>
      <p className="muted">Hashing reads the whole file. Larger files get the header check only, and the inventory records that no hash was computed.</p>

      <h2>Discovery</h2>
      <label>Ignored names (one pattern per line)<textarea rows={4} value={ignore} spellCheck={false} onChange={e => setIgnore(e.target.value)} /></label>
      <label>Settle time (seconds without change before inspection)<input value={stability} inputMode="numeric" onChange={e => setStability(e.target.value)} /></label>
      <label>Crawl interval (seconds between complete crawls)<input value={interval} inputMode="numeric" onChange={e => setIntervalSeconds(e.target.value)} /></label>
      {error && <p role="alert" className="error"><ErrorMessage message={error} /></p>}
      <Button type="submit" disabled={busy || Boolean(locationId && existing.data?.policy_invalid)}>Review</Button>
    </form>}
    <Dialog open={review} locked={busy} onOpenChange={open => { if (!open && !busy) setReview(false) }}
      title={locationId ? 'Save this location?' : 'Create this location?'}
      description={locationId ? 'A policy change applies to files inspected afterwards; files already inspected are not re-judged until they change.'
        : 'The storage protection worker starts crawling it on its next sweep if the backend is mounted there.'}>
      <p><strong>{name.trim()}</strong> · {backend}:/{prefix.trim()}</p>
      <p>{defaultTier === 'light' ? 'Light tier by default' : 'Full tier by default'} · {rules.length} rule(s) ·
        {' '}{typeMode} of {families.length} famil{families.length === 1 ? 'y' : 'ies'}{enabled ? '' : ' · disabled'}</p>
      <div className="report-actions"><Button variant="secondary" disabled={busy} onClick={() => setReview(false)}>Cancel</Button>
        <Button disabled={busy} onClick={() => { void save() }}>{busy ? 'Saving…' : 'Confirm'}</Button></div>
    </Dialog>
  </section>
}
