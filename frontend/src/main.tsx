import { lazy, Suspense, useEffect, useState, type FormEvent } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { BrowserRouter, Link, NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { Activity, CircleUser, Cpu, Hash, Info, LayoutDashboard, LogOut, Plug, ScrollText, Server, SlidersHorizontal, Upload, Users as UsersIcon } from 'lucide-react'
import { request } from './lib/api'
import { Button } from './components/ui/button'
import { ThemeToggle } from './components/theme-toggle'
import './styles.css'

const Users = lazy(() => import('./pages/users'))
const Account = lazy(() => import('./pages/account'))
const Engines = lazy(() => import('./pages/engines'))
const Dashboard = lazy(() => import('./pages/dashboard'))
const NewScan = lazy(() => import('./pages/new-scan'))
const Report = lazy(() => import('./pages/scan-report'))
const AutomationResult = lazy(() => import('./pages/automation-result'))
const EngineOutput = lazy(() => import('./pages/engine-output'))
const ArchiveChildren = lazy(() => import('./pages/archive-children'))
const ScanManagement = lazy(() => import('./pages/scan-management'))
const BatchJson = lazy(() => import('./pages/batch-json'))
const BatchOverview = lazy(() => import('./pages/batch-overview'))
const System = lazy(() => import('./pages/system'))
const WorkerPools = lazy(() => import('./pages/worker-pools'))
const Runtime = lazy(() => import('./pages/runtime'))
const SystemOverview = lazy(() => import('./pages/system-overview'))
const Retention = lazy(() => import('./pages/retention'))
const ScanPolicy = lazy(() => import('./pages/scan-policy'))
const HashScan = lazy(() => import('./pages/hash-scan'))
const AutomationManagement = lazy(() => import('./pages/automation-management'))
const ApiLedger = lazy(() => import('./pages/api-ledger'))
const ServiceClients = lazy(() => import('./pages/service-clients'))
const ClientCredentials = lazy(() => import('./pages/client-credentials'))
const ClientProfiles = lazy(() => import('./pages/client-profiles'))
const Audit = lazy(() => import('./pages/audit'))
const About = lazy(() => import('./pages/about'))
const ScanPrint = lazy(() => import('./pages/scan-print'))
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
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    const expired = () => { clearPrivateQueries(); client.setQueryData(['session'], null) }
    window.addEventListener('masp-session-expired', expired)
    return () => window.removeEventListener('masp-session-expired', expired)
  }, [])
  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(''); setNotice(''); setBusy(true)
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
  if (session.isPending) return <main className="login-shell"><ThemeToggle className="login-theme-toggle" /><p role="status">Connecting to MASP…</p></main>
  if (!session.data) return <main className="login-shell"><ThemeToggle className="login-theme-toggle" /><form className="login-card" onSubmit={login}>
    <img src="/console/favicon.svg" width="48" height="48" alt="MASP" /><p className="eyebrow">MASP CONSOLE</p>
    <h1>Welcome back.</h1><p className="muted">Sign in with your existing MASP account.</p>
    {notice && <p role="status" className="callout">{notice}</p>}
    <label>Username<input name="username" autoComplete="username" required autoFocus /></label>
    <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
    {(error || session.error) && <p role="alert" className="error">{error || session.error?.message}</p>}
    <Button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</Button>
  </form></main>
  return <div className="app-shell"><aside className="sidebar">
    <Link className="brand" to="/dashboard"><img src="/console/favicon.svg" width="40" height="40" alt="" /><span>MASP<small>SCAN ORCHESTRATION</small></span></Link>
    <p className="nav-label">WORKSPACE</p><nav className="console-nav" aria-label="Workspace">
    <NavLink className="nav-item" to="/dashboard"><LayoutDashboard size={18} />Dashboard</NavLink>
    <NavLink className="nav-item" to="/scans/new"><Upload size={18} />Submit sample</NavLink>
    <NavLink className="nav-item" to="/api-ledger"><Activity size={18} />API ledger</NavLink>
    <NavLink className="nav-item" to="/hash-scan"><Hash size={18} />Hash lookup</NavLink>
    <NavLink className="nav-item" to="/account"><CircleUser size={18} />Account</NavLink>
    <NavLink className="nav-item" to="/about"><Info size={18} />About</NavLink>
    {session.data.user.role === 'admin' && <NavLink className="nav-item" to="/engines"><Cpu size={18} />Engines</NavLink>}
    {session.data.user.role === 'admin' && <NavLink className="nav-item" to="/system"><Server size={18} />System</NavLink>}
    {session.data.user.role === 'admin' && <NavLink className="nav-item" to="/scan-policy"><SlidersHorizontal size={18} />Scan policy</NavLink>}
    {session.data.user.role === 'admin' && <NavLink className="nav-item" to="/service-clients"><Plug size={18} />Service clients</NavLink>}
    {session.data.user.role === 'admin' && <NavLink className="nav-item" to="/users"><UsersIcon size={18} />Users</NavLink>}
    {session.data.user.role === 'admin' && <NavLink className="nav-item" to="/audit"><ScrollText size={18} />Audit</NavLink>}
    </nav>
    <div className="sidebar-footer"><span>{session.data.user.username}<small>{session.data.user.role}</small></span><div className="sidebar-controls">
      <ThemeToggle /><Button variant="secondary" disabled={busy} onClick={logout} aria-label="Sign out"><LogOut size={17} /></Button></div></div>
  </aside><main className="workspace"><header className="topbar"><span>Workspace <span className="muted">/ {location.pathname === '/account' ? 'Account' : location.pathname === '/about' ? 'About' : location.pathname === '/audit' ? 'Audit trail' : location.pathname.endsWith('/print') ? 'Printable report' : location.pathname === '/users' ? 'Users' : location.pathname.startsWith('/api-ledger') ? 'API ledger' : location.pathname.startsWith('/service-clients') ? 'Service clients' : location.pathname === '/hash-scan' ? 'Hash lookup' : location.pathname === '/scan-policy' ? 'Scan policy' : location.pathname.startsWith('/system') ? 'System' : location.pathname === '/engines' ? 'Engine deployments' : location.pathname === '/scans/new' ? 'Submit sample' : location.pathname.startsWith('/batches/') ? 'Batch overview' : location.pathname.endsWith('/children') ? 'Archive contents' : location.pathname.startsWith('/scans/') ? 'Scan report' : 'Dashboard'}</span></span><span className="offline-label">SELF-HOSTED</span></header>
    {error && <p role="alert" className="error">{error}</p>}
      <Suspense fallback={<p role="status">Loading page…</p>}><Routes>
        <Route path="/account" element={<Account session={session.data} onPasswordChanged={() => {
          clearPrivateQueries(); client.setQueryData(['session'], null); setError(''); setNotice('Password updated. All your sessions were signed out. Sign in with your new password.')
        }} />} />
        <Route path="/users" element={session.data.user.role === 'admin' ? <Users session={session.data} /> : <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/about" element={<About session={session.data} />} />
        <Route path="/audit" element={session.data.user.role === 'admin' ? <Audit /> : <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/dashboard" element={<Dashboard session={session.data} />} />
        <Route path="/scans/new" element={<NewScan session={session.data} />} />
        <Route path="/api-ledger/scans/:scanId" element={<Report key={location.pathname} automation />} />
        <Route path="/api-ledger/scans/:scanId/results/:resultId" element={<EngineOutput key={location.pathname} automation />} />
        <Route path="/api-ledger/scans/:scanId/status-json" element={<AutomationResult key={location.pathname} status />} />
        <Route path="/api-ledger/scans/:scanId/result-json" element={<AutomationResult key={location.pathname} />} />
        <Route path="/api-ledger/scans/:scanId/manage" element={<AutomationManagement key={location.pathname} session={session.data} />} />
        <Route path="/api-ledger/batches/:batchId/status-json" element={<BatchJson key={location.pathname} status />} />
        <Route path="/api-ledger/batches/:batchId/result-json" element={<BatchJson key={location.pathname} />} />
        <Route path="/api-ledger/batches/:batchId" element={<BatchOverview key={location.pathname} automation />} />
        <Route path="/api-ledger" element={<ApiLedger session={session.data} />} />
        <Route path="/hash-scan" element={<HashScan session={session.data} />} />
        <Route path="/scans/:scanId" element={<Report />} />
        <Route path="/scans/:scanId/results/:resultId" element={<EngineOutput />} />
        <Route path="/scans/:scanId/manage" element={<ScanManagement key={location.pathname} session={session.data} />} />
        <Route path="/scans/:scanId/print" element={<ScanPrint key={location.pathname} />} />
        <Route path="/api-ledger/scans/:scanId/print" element={<ScanPrint key={location.pathname} automation />} />
        <Route path="/api-ledger/scans/:scanId/children" element={<ArchiveChildren key={location.pathname} automation />} />
        <Route path="/scans/:scanId/children" element={<ArchiveChildren />} />
        <Route path="/batches/:batchId" element={<BatchOverview />} />
        <Route path="/system/pools" element={session.data.user.role === 'admin' ? <WorkerPools session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/system/runtime" element={session.data.user.role === 'admin' ? <Runtime /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/service-clients/new" element={session.data.user.role === 'admin' ? <ClientCredentials key={location.pathname} create session={session.data} /> : <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/service-clients/:clientId/credentials" element={session.data.user.role === 'admin' ? <ClientCredentials key={location.pathname} session={session.data} /> : <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/service-clients/:clientId/profiles" element={session.data.user.role === 'admin' ? <ClientProfiles key={location.pathname} session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/service-clients" element={session.data.user.role === 'admin' ? <ServiceClients session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/scan-policy" element={session.data.user.role === 'admin' ? <ScanPolicy session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/system/retention" element={session.data.user.role === 'admin' ? <Retention session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/system/overview" element={session.data.user.role === 'admin' ? <SystemOverview /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/system" element={session.data.user.role === 'admin' ? <System session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1><p>Your session does not have system-management permissions.</p></section>} />
        <Route path="/engines" element={session.data.user.role === 'admin' ? <Engines session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1><p>Your session does not have engine-management permissions.</p></section>} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes></Suspense>
  </main></div>
}

createRoot(document.getElementById('root')!).render(
  <QueryClientProvider client={client}><BrowserRouter basename="/console"><App /></BrowserRouter></QueryClientProvider>,
)
