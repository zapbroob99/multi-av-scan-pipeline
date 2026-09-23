import { ShieldAlert, ShieldQuestion } from 'lucide-react'

const ALERT_LEVELS = new Set(['high', 'critical'])
const REVIEW_LEVELS = new Set(['medium', 'low'])

/** Recorded risk, shown so a detection is not just red text in a cell.
 *
 * The wording stays deliberately about what was *recorded*: a high score is not
 * a policy decision and a low one is not proof of clean coverage. The report is
 * still where the decision lives. */
export function RiskBadge({ level, score, pending = false }: { level: string; score: number | null; pending?: boolean }) {
  const normalized = (level || '').toLowerCase()
  // An unfinished scan has no recorded risk yet; saying "not scored" would read
  // as a finished result that produced nothing.
  if (pending) return <span className="risk-badge risk-badge-unscored">Pending</span>
  if (score === null) return <span className="risk-badge risk-badge-unscored">Not scored</span>
  const alert = ALERT_LEVELS.has(normalized)
  const review = REVIEW_LEVELS.has(normalized)
  return <span className={`risk-badge ${alert ? 'risk-badge-alert' : review ? 'risk-badge-review' : 'risk-badge-quiet'}`}>
    {alert && <ShieldAlert size={14} aria-hidden="true" />}
    {review && <ShieldQuestion size={14} aria-hidden="true" />}
    <strong>{normalized || 'unknown'}</strong>
    <span className="risk-badge-score">{score} / 100</span>
  </span>
}

/** True when a row should be called out in the list itself, not only in a cell. */
export function isAlertRisk(level: string): boolean {
  return ALERT_LEVELS.has((level || '').toLowerCase())
}
