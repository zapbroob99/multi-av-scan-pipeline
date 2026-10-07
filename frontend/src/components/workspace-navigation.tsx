import { useEffect, useRef, useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { request } from '../lib/api'
import { Activity, CircleUser, FolderSearch, Hash, Info, LayoutDashboard, Menu, Plug, ScrollText, Server, SlidersHorizontal, Upload, Users, X } from 'lucide-react'
import { Button } from './ui/button'

export function WorkspaceNavigation({ admin }: { admin: boolean }) {
  const location = useLocation()
  const [open, setOpen] = useState(false)
  const toggle = useRef<HTMLButtonElement>(null)
  useEffect(() => { setOpen(false) }, [location.pathname, location.search])
  // Folder scanning appears once it is in use: a worker has reported or a folder is watched.
  // An unreadable answer shows the entry rather than hiding a problem.
  const folders = useQuery({ queryKey: ['storage-presence'], queryFn: ({ signal }) => request('/api/ui/v1/storage/overview', 'get', { signal }),
    staleTime: 60_000, retry: false, refetchOnWindowFocus: false })
  const showFolders = folders.isError || location.pathname.startsWith('/storage')
    || Boolean(folders.data && (folders.data.worker || folders.data.worker_record_invalid || folders.data.locations.length))
  return <div className="workspace-navigation" onKeyDown={event => {
    if (event.key === 'Escape' && open) { setOpen(false); toggle.current?.focus() }
  }}>
    <Button ref={toggle} variant="secondary" className="navigation-toggle" aria-expanded={open} aria-controls="workspace-navigation"
      onClick={() => setOpen(value => !value)}>{open ? <X size={18} /> : <Menu size={18} />}Menu</Button>
    <nav id="workspace-navigation" className={`console-nav${open ? ' is-open' : ''}`} aria-label="Workspace" onClick={event => {
      if ((event.target as HTMLElement).closest('a')) setOpen(false)
    }}>
      <div className="nav-group"><p className="nav-label">Operations</p>
        <NavLink className="nav-item" to="/dashboard"><LayoutDashboard size={18} />Dashboard</NavLink>
        <NavLink className="nav-item" to="/scans/new"><Upload size={18} />Submit sample</NavLink>
        <NavLink className="nav-item" to="/hash-scan"><Hash size={18} />Hash lookup</NavLink>
        {showFolders && <NavLink className="nav-item" to="/storage"><FolderSearch size={18} />Folder scanning</NavLink>}
      </div>
      <div className="nav-group"><p className="nav-label">Integrations</p>
        <NavLink className="nav-item" to="/api-ledger"><Activity size={18} />API ledger</NavLink>
        {admin && <NavLink className="nav-item" to="/service-clients"><Plug size={18} />Service clients</NavLink>}
      </div>
      {admin && <><div className="nav-group"><p className="nav-label">Infrastructure</p>
        <NavLink to="/system/overview" className={() => `nav-item${location.pathname.startsWith('/system') || location.pathname.startsWith('/engines') ? ' active' : ''}`}>
          <Server size={18} />System</NavLink>
      </div><div className="nav-group"><p className="nav-label">Administration</p>
        <NavLink className="nav-item" to="/scan-policy"><SlidersHorizontal size={18} />Limits &amp; notifications</NavLink>
        <NavLink className="nav-item" to="/users"><Users size={18} />Users</NavLink>
        <NavLink className="nav-item" to="/audit"><ScrollText size={18} />Audit</NavLink>
      </div></>}
      <div className="nav-utilities">
        <NavLink className="nav-item" to="/account"><CircleUser size={17} />Account</NavLink>
        <NavLink className="nav-item" to="/about"><Info size={17} />About</NavLink>
      </div>
    </nav>
  </div>
}
