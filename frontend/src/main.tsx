import { lazy, Suspense, useEffect, useState, type FormEvent } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { BrowserRouter, Link, NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { Activity, ArrowUpRight, Cpu, LayoutDashboard, LogOut } from 'lucide-react'
import { request } from './lib/api'
import { Button } from './components/ui/button'
import './styles.css'

const Engines = lazy(() => import('./pages/engines'))
const Dashboard = lazy(() => import('./pages/dashboard'))
const NewScan = lazy(() => import('./pages/new-scan'))
const Report = lazy(() => import('./pages/scan-report'))
const ArchiveChildren = lazy(() => import('./pages/archive-children'))
const ScanManagement = lazy(() => import('./pages/scan-management'))
const BatchOverview = lazy(() => import('./pages/batch-overview'))
const client = new QueryClient({ defaultOptions: {
  queries: { staleTime: 15000, retry: false, refetchOnWindowFocus: false, refetchIntervalInBackground: false },
  mutations: { retry: false },
} })

function clearPrivateQueries() {
  // Keep the mounted session observer attached; clearing its query while it is
  // pending can leave the login screen stuck on "Connecting".
  client.removeQueries({ predicate: query => query.queryKey[0] !== 'session' })
}

function App() {
  const location = useLocation()
  const session = useQuery({ queryKey: ['session'], queryFn: ({ signal }) => request('/api/ui/v1/session', 'get', { signal }), retry: false })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    const expired = () => { clearPrivateQueries(); client.setQueryData(['session'], null) }
    window.addEventListener('masp-session-expired', expired)
    return () => window.removeEventListener('masp-session-expired', expired)
  }, [])
  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(''); setBusy(true)
    const form = new FormData(event.currentTarget)
    try {
      const result = await request('/api/ui/v1/session/login', 'post', { body: { username: String(form.get('username') || ''), password: String(form.get('password') || '') } })
      clearPrivateQueries(); client.setQueryData(['session'], result)
    } catch (e) { setError((e as Error).message) } finally { setBusy(false) }
  }
  async function logout() {
    setError(''); setBusy(true)
    try {
      await request('/api/ui/v1/session/logout', 'post', { csrf: session.data!.csrf_token })
      clearPrivateQueries(); client.setQueryData(['session'], null)
    } catch (e) { setError((e as Error).message) } finally { setBusy(false) }
  }
  if (session.isPending) return <main className="login-shell"><p role="status">Connecting to MASP…</p></main>
  if (!session.data) return <main className="login-shell"><form className="login-card" onSubmit={login}>
    <img src="/console/favicon.svg" width="48" height="48" alt="MASP" /><p className="eyebrow">MASP CONSOLE</p>
    <h1>Welcome back.</h1><p className="muted">Sign in with your existing MASP account.</p>
    <label>Username<input name="username" autoComplete="username" required autoFocus /></label>
    <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
    {(error || session.error) && <p role="alert" className="error">{error || session.error?.message}</p>}
    <Button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</Button>
  </form></main>
  return <div className="app-shell"><aside className="sidebar">
    <Link className="brand" to="/dashboard"><img src="/console/favicon.svg" width="40" height="40" alt="" /><span>MASP<small>SCAN ORCHESTRATION</small></span></Link>
    <p className="nav-label">WORKSPACE</p><nav className="console-nav" aria-label="Workspace">
    <NavLink className="nav-item" to="/dashboard"><LayoutDashboard size={18} />Dashboard</NavLink>
    <NavLink className="nav-item" to="/scans/new"><ArrowUpRight size={18} />Submit sample</NavLink>
    {session.data.user.role === 'admin' && <NavLink className="nav-item" to="/engines"><Cpu size={18} />Engines</NavLink>}
    </nav>
    <a className="nav-item" href="/system"><Activity size={18} />System <small>Legacy</small></a>
    <div className="sidebar-footer"><span>{session.data.user.username}<small>{session.data.user.role}</small></span>
      <Button variant="secondary" disabled={busy} onClick={logout} aria-label="Sign out"><LogOut size={17} /></Button></div>
  </aside><main className="workspace"><header className="topbar"><span>Workspace <span className="muted">/ {location.pathname === '/engines' ? 'Engine deployments' : location.pathname === '/scans/new' ? 'Submit sample' : location.pathname.startsWith('/batches/') ? 'Batch overview' : location.pathname.endsWith('/children') ? 'Archive contents' : location.pathname.startsWith('/scans/') ? 'Scan report' : 'Dashboard'}</span></span><span className="offline-label">SELF-HOSTED</span></header>
    {error && <p role="alert" className="error">{error}</p>}
      <Suspense fallback={<p role="status">Loading page…</p>}><Routes>
        <Route path="/dashboard" element={<Dashboard session={session.data} />} />
        <Route path="/scans/new" element={<NewScan session={session.data} />} />
        <Route path="/scans/:scanId" element={<Report />} />
        <Route path="/scans/:scanId/manage" element={<ScanManagement key={location.pathname} session={session.data} />} />
        <Route path="/scans/:scanId/children" element={<ArchiveChildren />} />
        <Route path="/batches/:batchId" element={<BatchOverview />} />
        <Route path="/engines" element={session.data.user.role === 'admin' ? <Engines session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1><p>Your session does not have engine-management permissions.</p></section>} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes></Suspense>
  </main></div>
}

createRoot(document.getElementById('root')!).render(
  <QueryClientProvider client={client}><BrowserRouter basename="/console"><App /></BrowserRouter></QueryClientProvider>,
)
