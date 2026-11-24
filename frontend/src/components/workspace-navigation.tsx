import { useEffect, useRef, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { CircleUser, FolderSearch, Info, LayoutDashboard, Menu, Plug, Server, ShieldCheck, SlidersHorizontal, X } from 'lucide-react'
import { visibleNavigation, navigationFor } from '../lib/navigation'
import { Button } from './ui/button'

const ICONS = { scans: LayoutDashboard, integrations: Plug, storage: FolderSearch, policies: ShieldCheck, infrastructure: Server, administration: SlidersHorizontal }

export function WorkspaceNavigation({ admin }: { admin: boolean }) {
  const location = useLocation()
  const [open, setOpen] = useState(false)
  const toggle = useRef<HTMLButtonElement>(null)
  const current = navigationFor(location.pathname)
  useEffect(() => { setOpen(false) }, [location.pathname, location.search])
  return <div className="workspace-navigation" onKeyDown={event => {
    if (event.key === 'Escape' && open) { setOpen(false); toggle.current?.focus() }
  }}>
    <Button ref={toggle} variant="secondary" className="navigation-toggle" aria-expanded={open} aria-controls="workspace-navigation"
      onClick={() => setOpen(value => !value)}>{open ? <X size={18} /> : <Menu size={18} />}Menu</Button>
    <nav id="workspace-navigation" className={`console-nav${open ? ' is-open' : ''}`} aria-label="Workspace" onClick={event => {
      if ((event.target as HTMLElement).closest('a')) setOpen(false)
    }}>
      <div className="nav-group">{visibleNavigation(admin).map(area => {
        const Icon = ICONS[area.id as keyof typeof ICONS]
        const active = current?.area.id === area.id
        return <Link key={area.id} className={`nav-item${active ? ' active' : ''}`} to={area.items[0].to} aria-current={active ? 'true' : undefined}>
          <Icon size={18} />{area.label}</Link>
      })}</div>
      <div className="nav-utilities">
        <Link className={`nav-item${location.pathname === '/account' ? ' active' : ''}`} to="/account" aria-current={location.pathname === '/account' ? 'page' : undefined}><CircleUser size={17} />Account</Link>
        <Link className={`nav-item${location.pathname === '/about' ? ' active' : ''}`} to="/about" aria-current={location.pathname === '/about' ? 'page' : undefined}><Info size={17} />About</Link>
      </div>
    </nav>
  </div>
}

export function AreaNavigation({ admin }: { admin: boolean }) {
  const location = useLocation()
  const current = navigationFor(location.pathname)
  if (!current || (current.area.admin && !admin)) return null
  const items = current.area.items.filter(item => admin || !item.admin)
  return <nav className="section-tabs" aria-label={`${current.area.label} sections`}>
    {items.map(item => <Link key={item.to} to={item.to} className={`section-tab${current.item.to === item.to ? ' active' : ''}`}
      aria-current={current.item.to === item.to ? 'page' : undefined}>{item.label}</Link>)}
  </nav>
}
