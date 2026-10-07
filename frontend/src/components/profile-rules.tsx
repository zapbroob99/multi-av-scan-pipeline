import { useId, useState, type FormEvent } from 'react'
import { ArrowDown, ArrowUp, Plus, Trash2 } from 'lucide-react'
import type { components } from '../lib/api.generated'
import { Button } from './ui/button'

export type RulesPolicy = components['schemas']['RulesPolicy']
type Rule = components['schemas']['Rule']
type Action = Rule['action']
type Archive = NonNullable<Rule['archive']>
type Inconclusive = RulesPolicy['inconclusive']
export type EngineChoice = components['schemas']['ProfileEngineChoice']

const MB = 1024 * 1024
export const FAMILY_SHORT: Record<string, string> = {
  executable: 'Programs', script: 'Scripts', archive: 'Archives', office: 'Office', pdf: 'PDF',
  image: 'Images', markup: 'XML', unrecognized: 'Unrecognized',
}
const FAMILIES = Object.keys(FAMILY_SHORT)
const ACTIONS: Record<Action, string> = { scan: 'Scan', light: 'Light check', allow: 'Allow without scanning', block: 'Block' }
const ARCHIVES: Record<Archive, string> = { whole: 'as one file', inspect: 'opened and checked', members: 'opened, every file inside scanned' }
export const INCONCLUSIVE_HELP = 'Not conclusive: an engine failed or did not finish, an engine asked for review, or the risk is elevated without a detection.'

function megabytes(bytes: number) {
  const value = bytes / MB
  return Number.isInteger(value) ? String(value) : String(Math.round(value * 100) / 100)
}

/** The rule's condition in words; the last rule matches every other file. */
export function conditionText(rule: Rule, last: boolean) {
  const when = rule.when ?? {}
  if (last) return 'Every other file'
  const parts: string[] = []
  const above = when.larger_than_bytes, upTo = when.up_to_bytes
  if (above != null && upTo != null) parts.push(`Size ${megabytes(above)}–${megabytes(upTo)} MB`)
  else if (above != null) parts.push(`Larger than ${megabytes(above)} MB`)
  else if (upTo != null) parts.push(`Up to ${megabytes(upTo)} MB`)
  if (when.families?.length) parts.push(`Type: ${when.families.map(family => FAMILY_SHORT[family] ?? family).join(', ')}`)
  if (when.masquerade) parts.push('Extension contradicts content')
  return parts.join(' · ')
}

export function actionText(rule: Rule, engines: EngineChoice[]) {
  const names = (rule.engines ?? []).map(id => engines.find(engine => engine.id === id)?.display_name ?? `engine #${id}`)
  if (rule.action === 'block') return 'Block'
  if (rule.action === 'allow') return 'Allow without scanning'
  const base = `${ACTIONS[rule.action]}: ${names.join(', ')}`
  return rule.archive && rule.archive !== 'whole' ? `${base} · archives ${ARCHIVES[rule.archive]}` : base
}

export function RulesTable({ rules, engines }: { rules: RulesPolicy; engines: EngineChoice[] }) {
  return <>
    <div className="history-table-wrap"><table className="rules-table">
      <thead><tr><th scope="col">#</th><th scope="col">When</th><th scope="col">Do</th></tr></thead>
      <tbody>{rules.rules.map((rule, index) => <tr key={index}>
        <td className="rules-number">{index + 1}</td>
        <td>{conditionText(rule, index === rules.rules.length - 1)}</td>
        <td className={`rules-action rules-action-${rule.action}`}>{actionText(rule, engines)}</td>
      </tr>)}</tbody></table></div>
    <p className="client-note rules-inconclusive">When the result is not conclusive: <strong>{rules.inconclusive === 'block' ? 'Block' : 'Allow, labelled Not fully scanned'}</strong></p>
  </>
}

type Draft = { above: string; upTo: string; families: string[]; masquerade: boolean; action: Action | ''; engines: number[]; archive: Archive | '' }

function toDraft(rule: Rule): Draft {
  const when = rule.when ?? {}
  return { above: when.larger_than_bytes != null ? megabytes(when.larger_than_bytes) : '',
    upTo: when.up_to_bytes != null ? megabytes(when.up_to_bytes) : '', families: when.families ?? [],
    masquerade: when.masquerade ?? false, action: rule.action, engines: rule.engines ?? [], archive: rule.archive ?? '' }
}

const EMPTY: Draft = { above: '', upTo: '', families: [], masquerade: false, action: '', engines: [], archive: '' }

/** Whether a rule with these conditions can match an archive, so it must say how it treats one. */
function matchesArchives(draft: Draft) {
  return !draft.families.length || draft.families.includes('archive')
}

function bytes(text: string, label: string): number | null {
  if (!text.trim()) return null
  const value = Number(text)
  if (!Number.isFinite(value) || value < 0) throw new Error(`${label}: enter a size in MB.`)
  return Math.round(value * MB)
}

function build(drafts: Draft[], inconclusive: Inconclusive | '', engines: EngineChoice[]): RulesPolicy {
  if (!inconclusive) throw new Error('Choose what happens when the result is not conclusive.')
  const rules = drafts.map((draft, index): Rule => {
    const last = index === drafts.length - 1
    const label = `Rule ${index + 1}`
    const above = last ? null : bytes(draft.above, `${label}, larger than`)
    const upTo = last ? null : bytes(draft.upTo, `${label}, up to`)
    if (above != null && upTo != null && upTo <= above) throw new Error(`${label}: the upper size must be larger than the lower size.`)
    if (!last && above == null && upTo == null && !draft.families.length && !draft.masquerade)
      throw new Error(`${label}: give it a condition; only the last rule matches every file.`)
    if (!draft.action) throw new Error(`${label}: choose what to do.`)
    const scanning = draft.action === 'scan' || draft.action === 'light'
    if (scanning && !draft.engines.length) throw new Error(`${label}: choose at least one engine.`)
    const chosen = draft.engines.map(id => engines.find(engine => engine.id === id))
    if (draft.action === 'scan' && !chosen.some(engine => engine?.detection))
      throw new Error(`${label}: Scan needs at least one antivirus or other detection engine; use Light check for checks only.`)
    const archives = draft.action === 'scan' && (last || matchesArchives(draft))
    if (archives && !draft.archive) throw new Error(`${label}: choose how archives are treated.`)
    return { when: last ? {} : { larger_than_bytes: above, up_to_bytes: upTo, families: draft.families, masquerade: draft.masquerade },
      action: draft.action, engines: scanning ? draft.engines : [], archive: archives ? draft.archive || null : null }
  })
  return { version: 2, rules, inconclusive }
}

function RuleRow({ draft, index, last, count, engines, update, move, remove }: {
  draft: Draft; index: number; last: boolean; count: number; engines: EngineChoice[]
  update: (patch: Partial<Draft>) => void; move: (offset: number) => void; remove: () => void
}) {
  const id = useId()
  // Choices: engines that run for API/ICAP files and fit the action, plus any
  // the rule already names, so a disabled one shows and can be removed.
  const offered = engines.filter(engine => draft.engines.includes(engine.id) || (!engine.excluded_reason
    && (draft.action === 'scan' || (draft.action === 'light' && !engine.detection))))
  const archives = draft.action === 'scan' && (last || matchesArchives(draft))
  return <li className="profile-rule-row" aria-label={`Rule ${index + 1}`}>
    <div className="profile-rule-row-heading"><strong>Rule {index + 1}</strong>
      {!last && <span className="profile-rule-row-tools">
        <Button type="button" variant="secondary" aria-label={`Move rule ${index + 1} up`} disabled={index === 0} onClick={() => move(-1)}><ArrowUp size={14} /></Button>
        <Button type="button" variant="secondary" aria-label={`Move rule ${index + 1} down`} disabled={index >= count - 2} onClick={() => move(1)}><ArrowDown size={14} /></Button>
        <Button type="button" variant="destructive" aria-label={`Remove rule ${index + 1}`} onClick={remove}><Trash2 size={14} /></Button></span>}</div>
    <div className="profile-rule-part"><span className="profile-rule-part-label">When</span>
      {last ? <p className="profile-rule-every">Every other file</p> : <div className="profile-rule-conditions">
        <div className="profile-rule-sizes">
          <label>Larger than (MB)<input inputMode="decimal" value={draft.above} onChange={event => update({ above: event.target.value })} /></label>
          <label>Up to (MB)<input inputMode="decimal" value={draft.upTo} onChange={event => update({ upTo: event.target.value })} /></label>
        </div>
        <fieldset className="profile-rule-families"><legend>Type (any of)</legend>
          {FAMILIES.map(family => <label key={family} className="check-row"><input type="checkbox" checked={draft.families.includes(family)}
            onChange={event => update({ families: event.target.checked ? [...draft.families, family] : draft.families.filter(item => item !== family) })} />{FAMILY_SHORT[family]}</label>)}
        </fieldset>
        <label className="check-row"><input type="checkbox" checked={draft.masquerade} onChange={event => update({ masquerade: event.target.checked })} />Extension contradicts content</label>
      </div>}
    </div>
    <div className="profile-rule-part"><span className="profile-rule-part-label">Do</span><div className="profile-rule-conditions">
      <label>Action<select id={`${id}-action`} value={draft.action} onChange={event => update({ action: event.target.value as Action, engines: [], archive: '' })}>
        <option value="" disabled>Choose…</option>
        {Object.entries(ACTIONS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      {(draft.action === 'scan' || draft.action === 'light') && <fieldset className="profile-rule-engines"><legend>Engines</legend>
        {!offered.length && <p className="muted">No engine fits this action.</p>}
        {offered.map(engine => <label key={engine.id} className="check-row"><input type="checkbox" checked={draft.engines.includes(engine.id)}
          onChange={event => update({ engines: event.target.checked ? [...draft.engines, engine.id] : draft.engines.filter(item => item !== engine.id) })} />
          {engine.display_name}{engine.excluded_reason ? ` (${engine.excluded_reason})` : ''}</label>)}
      </fieldset>}
      {archives && <label>Archives<select value={draft.archive} onChange={event => update({ archive: event.target.value as Archive })}>
        <option value="" disabled>Choose…</option>
        <option value="whole">Scan as one file</option>
        <option value="inspect">Open and check (block encrypted, damaged or refused content)</option>
        <option value="members">Open and scan every file inside</option></select></label>}
    </div></div>
  </li>
}

export function RulesEditor({ name, rules, engines, disabled, onCancel, onReview }: {
  name: string; rules: RulesPolicy | null; engines: EngineChoice[]; disabled: boolean
  onCancel: () => void; onReview: (rules: RulesPolicy) => void
}) {
  const [drafts, setDrafts] = useState<Draft[]>(rules ? rules.rules.map(toDraft) : [{ ...EMPTY }])
  const [inconclusive, setInconclusive] = useState<Inconclusive | ''>(rules?.inconclusive ?? '')
  const [error, setError] = useState('')
  const helpId = useId()
  const update = (index: number) => (patch: Partial<Draft>) => setDrafts(current => current.map((draft, at) => at === index ? { ...draft, ...patch } : draft))
  const move = (index: number) => (offset: number) => setDrafts(current => {
    const next = [...current]; const [item] = next.splice(index, 1); next.splice(index + offset, 0, item); return next
  })
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    try { onReview(build(drafts, inconclusive, engines)) } catch (problem) { setError((problem as Error).message) }
  }
  return <form className="submission-card rules-editor" onSubmit={submit}><fieldset disabled={disabled}>
    <legend className="client-form-title">Rules for {name}</legend>
    <p className="muted client-note">A file takes the first rule it matches, from the top. The last rule catches every other file. Changes apply to files accepted from now on.</p>
    {!rules && <p role="alert">This profile has no readable rules. Saving replaces whatever is stored with the rules below.</p>}
    <ol className="profile-rule-list">{drafts.map((draft, index) => <RuleRow key={index} draft={draft} index={index} last={index === drafts.length - 1}
      count={drafts.length} engines={engines} update={update(index)} move={move(index)}
      remove={() => setDrafts(current => current.filter((_, at) => at !== index))} />)}</ol>
    <Button type="button" variant="secondary" disabled={drafts.length >= 50}
      onClick={() => setDrafts(current => [...current.slice(0, -1), { ...EMPTY }, current[current.length - 1]])}><Plus size={14} aria-hidden="true" />Add rule</Button>
    <div className="field-with-help rules-inconclusive-choice"><label>When the result is not conclusive<select value={inconclusive} aria-describedby={helpId}
      onChange={event => setInconclusive(event.target.value as Inconclusive)}>
      <option value="" disabled>Choose…</option><option value="block">Block</option><option value="allow">Allow, labelled Not fully scanned</option></select></label>
      <small id={helpId} className="field-help">{INCONCLUSIVE_HELP}</small></div>
    {error && <p role="alert" className="error">{error}</p>}
    <div className="client-form-footer"><Button type="button" variant="secondary" onClick={onCancel}>Cancel</Button><Button type="submit">Review rules</Button></div>
  </fieldset></form>
}
