import { ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'

const ALERT_LEVELS = new Set(['high', 'critical'])
const REVIEW_LEVELS = new Set(['medium', 'low'])

/** Human label for a recorded risk level, used by badges and filters. */
export const RISK_LABELS: Record<string, string> = {
  pending: 'Pending', info: 'No detection', metadata_only: 'Metadata only',
  low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical',
}

/** Recorded risk, shown so a detection is not just red text in a cell.
 *
 * The wording stays deliberately about what was *recorded*: a high score is not
 * a policy decision, and "No detection" is not proof of clean coverage — the
 * report is still where the decision lives. When engines failed or were
 * skipped, that is shown instead of a quiet "No detection". */
export function RiskBadge({ level, score, pending = false, failed = false, unavailable = null }: {
  level: string; score: number | null; pending?: boolean; failed?: boolean; unavailable?: number | null
}) {
  const normalized = (level || '').toLowerCase()
  // An unfinished scan has no recorded risk yet; saying "not scored" would read
  // as a finished result that produced nothing.
  if (pending) return <span className="risk-badge risk-badge-unscored">Pending</span>
  // A failed scan has no outcome, whatever score an older record carries:
  // "No detection" beside "Failed" would read as a clean result.
  if (score === null || failed) return <span className="risk-badge risk-badge-unscored">Not scored</span>
  const alert = ALERT_LEVELS.has(normalized)
  // Before scoring stopped adding points for a clean result, every clean scan
  // was recorded as "low" with 10 points. Nothing else could produce that pair.
  const noDetection = normalized === 'info' || (normalized === 'low' && score <= 10)
  if (!alert && unavailable) return <span className="risk-badge risk-badge-review"
    title={`${unavailable} engine${unavailable === 1 ? '' : 's'} failed or were skipped. Open the report for coverage.`}>
    <ShieldQuestion size={14} aria-hidden="true" /><strong>Incomplete</strong>
    <span className="risk-badge-score">{unavailable} engine{unavailable === 1 ? '' : 's'} did not run</span></span>
  if (noDetection) return <span className="risk-badge risk-badge-clear" title="No completed engine reported a detection. This is not an allow decision.">
    <ShieldCheck size={14} aria-hidden="true" /><strong>No detection</strong></span>
  const review = REVIEW_LEVELS.has(normalized)
  return <span className={`risk-badge ${alert ? 'risk-badge-alert' : review ? 'risk-badge-review' : 'risk-badge-quiet'}`}>
    {alert && <ShieldAlert size={14} aria-hidden="true" />}
    {review && <ShieldQuestion size={14} aria-hidden="true" />}
    <strong>{RISK_LABELS[normalized] || normalized || 'unknown'}</strong>
    <span className="risk-badge-score">{score} / 100</span>
  </span>
}

/** True when a row should be called out in the list itself, not only in a cell. */
export function isAlertRisk(level: string): boolean {
  return ALERT_LEVELS.has((level || '').toLowerCase())
}
