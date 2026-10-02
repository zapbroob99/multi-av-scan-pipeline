import { useState, type FormEvent } from 'react'
import type { components } from '../lib/api.generated'
import { FAMILY_LABELS, formatBytes } from '../lib/storage'
import { Button } from './ui/button'

export type ProfilePolicy = components['schemas']['ProfilePolicy']
type TypeMode = 'none' | 'allowlist' | 'denylist'

const FAMILIES = Object.keys(FAMILY_LABELS)
const MIB = 1024 * 1024

/** One line per rule that differs from inheriting the deployment's behaviour. */
export function policySummary(policy: ProfilePolicy): string[] {
  const lines: string[] = []
  if (policy.max_file_bytes) lines.push(`Files larger than ${formatBytes(policy.max_file_bytes)} are rejected.`)
  const rule = policy.type_rule
  if (rule) lines.push(`${rule.mode === 'allowlist' ? 'Only' : 'Not'} accepted: ${rule.families.join(', ')}.`)
  if (policy.block_masquerade) lines.push('Files whose extension contradicts their content are not accepted.')
  if (rule || policy.block_masquerade) lines.push(policy.violation_action === 'reject'
    ? 'Content that is not accepted is rejected without scanning.'
    : 'Content that is not accepted is scanned and blocked.')
  if (policy.review_action === 'block') lines.push('Files that could not be fully assessed are blocked.')
  return lines
}

export function PolicySummary({ policy, invalid }: { policy: ProfilePolicy | null; invalid: boolean }) {
  if (invalid || !policy) return <p role="alert">The stored policy cannot be read. Scans under it are not allowed automatically until a new policy is saved.</p>
  const lines = policySummary(policy)
  if (!lines.length) return <p className="muted client-note">No rules of its own: the deployment's limits and review handling apply.</p>
  return <ul className="profile-policy-summary">{lines.map(line => <li key={line}>{line}</li>)}</ul>
}

export function ProfilePolicyEditor({ name, policy, invalid, disabled, onCancel, onReview }: {
  name: string; policy: ProfilePolicy | null; invalid: boolean; disabled: boolean
  onCancel: () => void; onReview: (policy: ProfilePolicy) => void
}) {
  const start = policy ?? {}
  const [sizeMib, setSizeMib] = useState(start.max_file_bytes ? String(Math.round(start.max_file_bytes / MIB * 100) / 100) : '')
  const [typeMode, setTypeMode] = useState<TypeMode>(start.type_rule?.mode ?? 'none')
  const [families, setFamilies] = useState<string[]>(start.type_rule?.families ?? ['executable', 'script'])
  const [masquerade, setMasquerade] = useState(start.block_masquerade ?? false)
  const [violation, setViolation] = useState(start.violation_action ?? 'scan_and_block')
  const [review, setReview] = useState(start.review_action ?? 'inherit')
  const [error, setError] = useState('')

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    let maxBytes: number | null = null
    if (sizeMib.trim()) {
      const value = Number(sizeMib)
      if (!Number.isFinite(value) || value <= 0) { setError('Enter a size in MiB greater than zero, or leave it blank.'); return }
      maxBytes = Math.max(1, Math.round(value * MIB))
    }
    if (typeMode !== 'none' && !families.length) { setError('Choose at least one content family, or turn the content rule off.'); return }
    if (typeMode === 'allowlist' && families.length === FAMILIES.length) { setError('An allowlist of every family accepts everything; turn the content rule off instead.'); return }
    onReview({
      max_file_bytes: maxBytes,
      type_rule: typeMode === 'none' ? null : { mode: typeMode, families: FAMILIES.filter(family => families.includes(family)) },
      block_masquerade: masquerade,
      violation_action: violation,
      review_action: review,
    })
  }

  const contentRules = typeMode !== 'none' || masquerade
  return <form className="submission-card" onSubmit={submit}><fieldset disabled={disabled}>
    <legend className="client-form-title">Scan policy for {name}</legend>
    <p className="muted client-note">Applies to scans this profile accepts from now on. Accepted scans keep the policy they were accepted under.
      A policy can only make a decision stricter; it never allows what the engines would not.</p>
    {invalid && <p role="alert">The stored policy cannot be read. Saving replaces it with the policy below.</p>}
    <label>Largest accepted file (MiB)<input inputMode="decimal" value={sizeMib} placeholder="Deployment limit" onChange={event => setSizeMib(event.target.value)} />
      <small className="muted">Blank: only the deployment's upload and ICAP limits apply. Larger files are rejected without scanning (ICAP blocks them, the API answers 413).</small></label>
    <label>Content rule<select value={typeMode} onChange={event => setTypeMode(event.target.value as TypeMode)}>
      <option value="none">None: every content family is accepted</option>
      <option value="denylist">Denylist: the families below are not accepted</option>
      <option value="allowlist">Allowlist: only the families below are accepted</option></select>
      <small className="muted">Judged from the file's first bytes, not its name. Plain text and CSV have no signature and count as unrecognized.</small></label>
    {typeMode !== 'none' && <fieldset className="check-grid"><legend>Content families</legend>
      {FAMILIES.map(family => <label key={family} className="check-row"><input type="checkbox" checked={families.includes(family)}
        onChange={event => setFamilies(event.target.checked ? [...families, family] : families.filter(item => item !== family))} /> {FAMILY_LABELS[family]}</label>)}</fieldset>}
    <label className="check-row"><input type="checkbox" checked={masquerade} onChange={event => setMasquerade(event.target.checked)} />
      Do not accept files whose extension contradicts their content (for example an executable named report.pdf)</label>
    {contentRules && <label>When content is not accepted<select value={violation} onChange={event => setViolation(event.target.value as typeof violation)}>
      <option value="scan_and_block">Scan it and block it: engine results are recorded</option>
      <option value="reject">Reject it without scanning: faster, no scan record (ICAP blocks, the API answers 415)</option></select></label>}
    <label>Files that could not be fully assessed<select value={review} onChange={event => setReview(event.target.value as typeof review)}>
      <option value="inherit">Deployment behaviour: the decision stays review</option>
      <option value="block">Block them</option></select>
      <small className="muted">An engine that failed or timed out leaves a file unassessed. Blocking is safer; while an engine is down, every file from this client is blocked.
        With the deployment behaviour, an ICAP gateway follows MASP_ICAP_BLOCK_ON_REVIEW and the API returns review.</small></label>
    {error && <p role="alert" className="error">{error}</p>}
    <div className="client-form-footer"><Button type="button" variant="secondary" onClick={onCancel}>Cancel</Button><Button type="submit">Review policy</Button></div>
  </fieldset></form>
}
