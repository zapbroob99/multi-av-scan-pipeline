import { NavLink, useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Button } from './ui/button'

export type Tab = { to: string; label: string; end?: boolean }

/** The System screens are one area, so every page shows the same tab strip and
 * marks the one it is on. They previously carried ad-hoc link lists that
 * differed per page and never included the current page, so there was no way
 * back from some of them. */
export const SYSTEM_TABS: Tab[] = [
  { to: '/system/overview', label: 'Overview' },
  { to: '/system', label: 'Worker nodes', end: true },
  { to: '/system/pools', label: 'Worker pools' },
  { to: '/system/runtime', label: 'Runtime and queue' },
  { to: '/system/retention', label: 'Retention' },
  { to: '/engines', label: 'Engines', end: true },
  { to: '/engines/hash-list', label: 'Hash list' },
]

export function SectionTabs({ tabs, label }: { tabs: Tab[]; label: string }) {
  return <nav className="section-tabs" aria-label={label}>
    {tabs.map(tab => <NavLink key={tab.to} to={tab.to} end={tab.end} className="section-tab">{tab.label}</NavLink>)}
  </nav>
}

/** Explicit back control: several detail pages could only be left with the
 * browser's own back button. Falls back to a known route when this page was
 * opened directly, so the control never dead-ends. */
export function BackLink({ to, label = 'Back' }: { to: string; label?: string }) {
  const navigate = useNavigate()
  return <Button variant="secondary" className="back-link" onClick={() => {
    if (window.history.length > 1) navigate(-1)
    else navigate(to)
  }}><ArrowLeft size={16} />{label}</Button>
}
