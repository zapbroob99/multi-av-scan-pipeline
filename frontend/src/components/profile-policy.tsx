import { useId, useState, type FormEvent, type ReactNode } from 'react'
import type { components } from '../lib/api.generated'
import { FAMILY_LABELS, formatBytes } from '../lib/storage'
import { Button } from './ui/button'

export type ProfilePolicy = components['schemas']['ProfilePolicy']
type TypeMode = 'none' | 'allowlist' | 'denylist'
type ArchiveHandling = NonNullable<ProfilePolicy['archive_handling']>
type ViolationAction = NonNullable<ProfilePolicy['violation_action']>
type ReviewAction = NonNullable<ProfilePolicy['review_action']>

const FAMILIES = Object.keys(FAMILY_LABELS)
const MIB = 1024 * 1024

const ARCHIVE_HELP: Record<ArchiveHandling, string> = {
  inherit: 'The server decides. An ICAP gateway set to refuse archives (MASP_ICAP_BLOCK_ARCHIVES) blocks every zip, 7z and tar as Not allowed; '
    + 'otherwise, and over the API, an archive is scanned as one file.',
  inspect: 'Engines scan the archive as one file, and MASP opens it to block what they cannot see: encrypted, damaged or oversized archives, '
    + 'formats MASP cannot open (RAR, CAB, single-file gzip), and files inside that these rules refuse or the hash blocklist lists.',
  scan_members: 'Like checking, and every file inside is also scanned by this profile\'s engines. Slower: an ICAP gateway waits up to '
    + 'MASP_ICAP_WAIT_SECONDS for all of them, then follows its fail mode.',
}
const VIOLATION_HELP: Record<ViolationAction, string> = {
  scan_and_block: 'The engines still scan the file and the result is recorded; the file is blocked and listed as Not allowed.',
  reject: 'Faster, but no scan record is kept: an ICAP gateway blocks the file and the API answers 415.',
}
const REVIEW_HELP: Record<ReviewAction, string> = {
  inherit: 'The decision stays "review": an ICAP gateway follows its own setting (MASP_ICAP_BLOCK_ON_REVIEW) and the API returns review.',
  block: 'Safer, but while an engine is down every file from this client is blocked.',
}

/** One line per rule that differs from inheriting the deployment's behaviour. */
export function policySummary(policy: ProfilePolicy): string[] {
  const lines: string[] = []
  if (policy.max_file_bytes) lines.push(`Files larger than ${formatBytes(policy.max_file_bytes)} are rejected.`)
  const rule = policy.type_rule
  if (rule) lines.push(`${rule.mode === 'allowlist' ? 'Only' : 'Not'} accepted: ${rule.families.join(', ')}.`)
  if (policy.block_masquerade) lines.push('Files whose extension contradicts their content are not accepted.')
  if (policy.archive_handling === 'inspect') lines.push('Archives are opened and checked: encrypted, damaged, oversized or unsupported archives are blocked.')
  if (policy.archive_handling === 'scan_members') lines.push('Every file inside an archive is scanned; an archive is allowed only when all of them are.')
  const archives = policy.archive_handling === 'inspect' || policy.archive_handling === 'scan_members'
  if (rule || policy.block_masquerade || archives) lines.push(policy.violation_action === 'reject'
    ? 'Content that is not accepted is rejected without scanning.'
    : 'Content that is not accepted is scanned and blocked.')
  if (policy.review_action === 'block') lines.push('Files that could not be fully assessed are blocked.')
  return lines
}

export function PolicySummary({ policy, invalid }: { policy: ProfilePolicy | null; invalid: boolean }) {
  if (invalid || !policy) return <p role="alert">The stored rules cannot be read. Files under them are not allowed automatically until new rules are saved.</p>
  const lines = policySummary(policy)
  if (!lines.length) return <p className="muted client-note">No rules of its own: the server's limits and review handling apply.</p>
  return <ul className="profile-policy-summary">{lines.map(line => <li key={line}>{line}</li>)}</ul>
}

/** A control with its help text outside the label, so the accessible name stays exact. */
function Field({ label, help, children }: { label: string; help: ReactNode; children: (describedBy: string) => ReactNode }) {
  const id = useId()
  return <div className="field-with-help"><label>{label}{children(id)}</label><small id={id} className="field-help">{help}</small></div>
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
  const [violation, setViolation] = useState<ViolationAction>(start.violation_action ?? 'scan_and_block')
  const [review, setReview] = useState<ReviewAction>(start.review_action ?? 'inherit')
  const [archives, setArchives] = useState<ArchiveHandling>(start.archive_handling ?? 'inherit')
  const [error, setError] = useState('')
  const masqueradeHelp = useId()

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
      archive_handling: archives,
    })
  }

  const contentRules = typeMode !== 'none' || masquerade || archives !== 'inherit'
  return <form className="submission-card" onSubmit={submit}><fieldset disabled={disabled}>
    <legend className="client-form-title">File rules for {name}</legend>
    <p className="muted client-note">Applies to files accepted from now on. Rules only make a decision stricter; they never allow what the engines would block.</p>
    {invalid && <p role="alert">The stored rules cannot be read. Saving replaces them with the rules below.</p>}
    <Field label="Largest accepted file (MiB)" help="Blank: only the server's upload and ICAP limits apply. Larger files are refused without scanning.">
      {id => <input inputMode="decimal" value={sizeMib} placeholder="Server limit" aria-describedby={id} onChange={event => setSizeMib(event.target.value)} />}</Field>
    <Field label="Content rule" help="Judged from the file's first bytes, not its name. Plain text and CSV have no signature and count as unrecognized.">
      {id => <select value={typeMode} aria-describedby={id} onChange={event => setTypeMode(event.target.value as TypeMode)}>
        <option value="none">No content rule</option>
        <option value="denylist">Refuse these types</option>
        <option value="allowlist">Accept only these types</option></select>}</Field>
    {typeMode !== 'none' && <fieldset className="check-grid"><legend>Content families</legend>
      {FAMILIES.map(family => <label key={family} className="check-row"><input type="checkbox" checked={families.includes(family)}
        onChange={event => setFamilies(event.target.checked ? [...families, family] : families.filter(item => item !== family))} /> {FAMILY_LABELS[family]}</label>)}</fieldset>}
    <div className="field-with-help"><label className="check-row"><input type="checkbox" checked={masquerade} aria-describedby={masqueradeHelp} onChange={event => setMasquerade(event.target.checked)} />
      Refuse files whose extension contradicts their content</label><small id={masqueradeHelp} className="field-help">For example a program named report.pdf.</small></div>
    <Field label="Archive handling (zip, 7z, tar)" help={ARCHIVE_HELP[archives]}>
      {id => <select value={archives} aria-describedby={id} onChange={event => setArchives(event.target.value as ArchiveHandling)}>
        <option value="inherit">Server setting</option>
        <option value="inspect">Check archives (recommended)</option>
        <option value="scan_members">Scan every file inside</option></select>}</Field>
    {contentRules && <Field label="When content is not accepted" help={VIOLATION_HELP[violation]}>
      {id => <select value={violation} aria-describedby={id} onChange={event => setViolation(event.target.value as ViolationAction)}>
        <option value="scan_and_block">Scan and block (recommended)</option>
        <option value="reject">Refuse without scanning</option></select>}</Field>}
    <Field label="Files that could not be fully assessed" help={<>An engine that failed or timed out leaves a file unassessed. {REVIEW_HELP[review]}</>}>
      {id => <select value={review} aria-describedby={id} onChange={event => setReview(event.target.value as ReviewAction)}>
        <option value="inherit">Server setting</option>
        <option value="block">Block them</option></select>}</Field>
    {error && <p role="alert" className="error">{error}</p>}
    <div className="client-form-footer"><Button type="button" variant="secondary" onClick={onCancel}>Cancel</Button><Button type="submit">Review rules</Button></div>
  </fieldset></form>
}
