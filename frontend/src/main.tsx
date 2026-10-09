import { lazy, Suspense, useEffect, useState, type FormEvent } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { LogOut } from 'lucide-react'
import { ApiError, request } from './lib/api'
import { Button } from './components/ui/button'
import { ThemeToggle } from './components/theme-toggle'
import { BrandMark } from './components/brand-mark'
import { SystemLayout } from './components/section-tabs'
import { WorkspaceNavigation } from './components/workspace-navigation'
import { ErrorMessage } from './components/error-message'
import { NotificationBell } from './components/notifications'
import '@fontsource/ibm-plex-sans/latin-400.css'
import '@fontsource/ibm-plex-sans/latin-ext-400.css'
import '@fontsource/ibm-plex-sans/latin-500.css'
import '@fontsource/ibm-plex-sans/latin-ext-500.css'
import '@fontsource/ibm-plex-sans/latin-600.css'
import '@fontsource/ibm-plex-sans/latin-ext-600.css'
import '@fontsource/ibm-plex-mono/latin-400.css'
import '@fontsource/ibm-plex-mono/latin-500.css'
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
const ClientStorage = lazy(() => import('./pages/client-storage'))
const ClientSetup = lazy(() => import('./pages/client-setup'))
const Audit = lazy(() => import('./pages/audit'))
const HashList = lazy(() => import('./pages/hash-list'))
// Only the sign-in screen draws it, so it loads in its own chunk.
const LoginScene = lazy(() => import('./components/login-scene').then(module => ({ default: module.LoginScene })))
const Exceptions = lazy(() => import('./pages/exceptions'))
const Intake = lazy(() => import('./pages/intake'))
const Delivery = lazy(() => import('./pages/delivery'))
const About = lazy(() => import('./pages/about'))
const ScanPrint = lazy(() => import('./pages/scan-print'))
const Storage = lazy(() => import('./pages/storage'))
const StorageLayout = lazy(() => import('./pages/storage').then(module => ({ default: module.StorageLayout })))
const StorageLocation = lazy(() => import('./pages/storage-location'))
const StorageLocationForm = lazy(() => import('./pages/storage-location-form'))
const StorageFindings = lazy(() => import('./pages/storage-findings'))
const client = new QueryClient({ defaultOptions: {
  queries: { staleTime: 15000, retry: false, refetchOnWindowFocus: false, refetchIntervalInBackground: false },
  mutations: { retry: false },
} })

const SECTIONS: [string, string, string][] = [
  ['/account', 'Personal', 'Account'], ['/about', 'Personal', 'About'], ['/audit', 'Administration', 'Audit trail'],
  ['/users', 'Administration', 'Users'], ['/scan-policy', 'Administration', 'Limits & notifications'],
  ['/api-ledger', 'Integrations', 'API ledger'], ['/service-clients', 'Integrations', 'Service clients'],
  ['/storage', 'Operations', 'Folder scanning'], ['/hash-scan', 'Operations', 'Hash lookup'],
  ['/engines/hash-list', 'Infrastructure', 'Hash list'], ['/engines/exceptions', 'Infrastructure', 'Exceptions'], ['/engines', 'Infrastructure', 'Engines'], ['/system', 'Infrastructure', 'System'],
  ['/scans/new', 'Operations', 'Submit sample'], ['/batches/', 'Operations', 'Batch overview'],
]

function locationTrail(pathname: string): [string, string] {
  if (pathname.endsWith('/print')) return ['Operations', 'Printable report']
  if (pathname.endsWith('/children')) return ['Operations', 'Archive contents']
  const match = SECTIONS.find(([prefix]) => pathname === prefix || pathname.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`) || pathname.startsWith(prefix))
  if (match) return [match[1], match[2]]
  if (pathname.startsWith('/scans/')) return ['Operations', 'Scan report']
  return ['Operations', 'Dashboard']
}

function initials(name: string) {
  const parts = name.split(/[^A-Za-z0-9]+/).filter(Boolean)
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : name.slice(0, 2)).toUpperCase()
}

function clearPrivateQueries() {
  // Keep the mounted session observer attached; clearing its query while it is
  // pending can leave the login screen stuck on "Connecting".
  client.removeQueries({ predicate: query => query.queryKey[0] !== 'session' })
}

function App() {
  const location = useLocation()
  const session = useQuery({ queryKey: ['session'], queryFn: ({ signal }) => request('/api/ui/v1/session', 'get', { signal }), retry: false })
  const loginOptions = useQuery({ queryKey: ['login-options'], enabled: session.isFetched && !session.data,
    queryFn: ({ signal }) => request('/api/ui/v1/session/options', 'get', { signal }), retry: false, staleTime: 60000 })
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
  // Not being signed in is the reason this form is shown, not an error to report.
  const sessionError = session.error && !(session.error instanceof ApiError && session.error.status === 401) ? session.error.message : ''
  const aside = <aside className="login-aside">
    <div><span className="brand"><BrandMark size={30} /><span>MASP<small>Scan orchestration</small></span></span>
      <h2>Multi-engine malware scanning on your own infrastructure.</h2></div>
    <footer>Authorized personnel only. Activity is recorded.</footer>
  </aside>
  if (session.isPending) return <main className="login-shell">{aside}<div className="login-main"><ThemeToggle className="login-theme-toggle" /><p role="status">Connecting to MASP…</p></div></main>
  // The form lives on the rail; the area to its right is the scene alone.
  if (!session.data) return <main className="login-shell login-shell-scene"><aside className="login-aside login-aside-form">
    <div><div className="login-aside-header"><span className="brand"><BrandMark size={30} /><span>MASP<small>Scan orchestration</small></span></span>
      <ThemeToggle /></div>
      <h2>Multi-engine malware scanning on your own infrastructure.</h2></div>
    <form className="login-card" onSubmit={login}>
      <BrandMark size={48} label="MASP" />
      <h1>Sign in to MASP</h1><p className="muted">Use your MASP account{loginOptions.data?.directory_login_enabled ? ' or your directory credentials' : ''}.</p>
      {notice && <p role="status" className="callout">{notice}</p>}
      <label>Username<input name="username" autoComplete="username" required autoFocus /></label>
      <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
      {(error || sessionError) && <p role="alert" className="error"><ErrorMessage message={error || sessionError} /></p>}
      <Button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</Button>
    </form>
    <footer>Authorized personnel only. Activity is recorded.</footer>
  </aside><div className="login-main login-main-scene"><Suspense fallback={null}><LoginScene /></Suspense></div></main>
  const [section, title] = locationTrail(location.pathname)
  return <div className="app-shell"><aside className="sidebar">
    <Link className="brand" to="/dashboard"><BrandMark size={28} /><span>MASP<small>Scan orchestration</small></span></Link>
    <WorkspaceNavigation admin={session.data.user.role === 'admin'} />
  </aside><main className="workspace"><header className="topbar">
    <ol className="breadcrumb" aria-label="Location"><li>MASP</li><li>{section}</li><li>{title}</li></ol>
    <div className="topbar-status"><span className="offline-label">SELF-HOSTED</span>
      <NotificationBell admin={session.data.user.role === 'admin'} csrf={session.data.csrf_token} />
      <span className="topbar-divider" aria-hidden="true" />
      <div className="topbar-user"><span className="user-avatar" aria-hidden="true">{initials(session.data.user.username)}</span>
        <span className="user-identity"><strong>{session.data.user.username}</strong><small>{session.data.user.role}</small></span>
        <ThemeToggle /><Button variant="secondary" disabled={busy} onClick={logout} aria-label="Sign out" title="Sign out"><LogOut size={16} /></Button></div></div>
  </header>
    {error && <p role="alert" className="error"><ErrorMessage message={error} /></p>}
      <Suspense fallback={<p role="status">Loading page…</p>}><Routes>
        <Route path="/account" element={<Account session={session.data} onPasswordChanged={() => {
          clearPrivateQueries(); client.setQueryData(['session'], null); setError(''); setNotice('Password updated. All your sessions were signed out. Sign in with your new password.')
        }} />} />
        <Route path="/users" element={session.data.user.role === 'admin' ? <Users session={session.data} /> : <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/about" element={<About session={session.data} />} />
        <Route path="/audit" element={session.data.user.role === 'admin' ? <Audit /> : <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/dashboard" element={<Dashboard session={session.data} />} />
        <Route path="/scans/new" element={<NewScan session={session.data} />} />
        <Route path="/api-ledger/scans/:scanId" element={<Report key={location.pathname} automation session={session.data} />} />
        <Route path="/api-ledger/scans/:scanId/results/:resultId" element={<EngineOutput key={location.pathname} automation />} />
        <Route path="/api-ledger/scans/:scanId/status-json" element={<AutomationResult key={location.pathname} status />} />
        <Route path="/api-ledger/scans/:scanId/result-json" element={<AutomationResult key={location.pathname} />} />
        <Route path="/api-ledger/scans/:scanId/manage" element={<AutomationManagement key={location.pathname} session={session.data} />} />
        <Route path="/api-ledger/batches/:batchId/status-json" element={<BatchJson key={location.pathname} status />} />
        <Route path="/api-ledger/batches/:batchId/result-json" element={<BatchJson key={location.pathname} />} />
        <Route path="/api-ledger/batches/:batchId" element={<BatchOverview key={location.pathname} automation />} />
        <Route path="/api-ledger" element={<ApiLedger session={session.data} />} />
        <Route path="/hash-scan" element={<HashScan session={session.data} />} />
        <Route element={<StorageLayout />}>
          <Route path="/storage" element={<Storage session={session.data} />} />
          <Route path="/storage/findings" element={<StorageFindings />} />
        </Route>
        <Route path="/storage/locations/new" element={<StorageLocationForm key={location.pathname} session={session.data} />} />
        <Route path="/storage/locations/:locationId/edit" element={<StorageLocationForm key={location.pathname} session={session.data} />} />
        <Route path="/storage/locations/:locationId" element={<StorageLocation key={location.pathname} session={session.data} />} />
        <Route path="/scans/:scanId" element={<Report session={session.data} />} />
        <Route path="/scans/:scanId/results/:resultId" element={<EngineOutput />} />
        <Route path="/scans/:scanId/manage" element={<ScanManagement key={location.pathname} session={session.data} />} />
        <Route path="/scans/:scanId/print" element={<ScanPrint key={location.pathname} />} />
        <Route path="/api-ledger/scans/:scanId/print" element={<ScanPrint key={location.pathname} automation />} />
        <Route path="/api-ledger/scans/:scanId/children" element={<ArchiveChildren key={location.pathname} automation />} />
        <Route path="/scans/:scanId/children" element={<ArchiveChildren />} />
        <Route path="/batches/:batchId" element={<BatchOverview />} />
        <Route path="/service-clients/new" element={session.data.user.role === 'admin' ? <ClientCredentials key={location.pathname} create session={session.data} /> : <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/service-clients/:clientId/credentials" element={session.data.user.role === 'admin' ? <ClientCredentials key={location.pathname} session={session.data} /> : <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/service-clients/:clientId/setup" element={session.data.user.role === 'admin' ? <ClientSetup key={location.pathname} /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/service-clients/:clientId/profiles" element={session.data.user.role === 'admin' ? <ClientProfiles key={location.pathname} session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/service-clients/:clientId/storage" element={session.data.user.role === 'admin' ? <ClientStorage key={location.pathname} session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/service-clients" element={session.data.user.role === 'admin' ? <ServiceClients session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route path="/scan-policy" element={session.data.user.role === 'admin' ? <ScanPolicy session={session.data} /> :
          <section className="empty"><h1>Administrator access required</h1></section>} />
        <Route element={session.data.user.role === 'admin' ? <SystemLayout /> : <section className="empty"><h1>Administrator access required</h1><p>Your session does not have system-management permissions.</p></section>}>
          <Route path="/system/pools" element={<WorkerPools session={session.data} />} />
          <Route path="/system/runtime" element={<Runtime />} />
          <Route path="/system/intake" element={<Intake session={session.data} />} />
          <Route path="/system/delivery" element={<Delivery session={session.data} />} />
          <Route path="/system/retention" element={<Retention session={session.data} />} />
          <Route path="/system/overview" element={<SystemOverview session={session.data} />} />
          <Route path="/system" element={<System session={session.data} />} />
          <Route path="/engines/hash-list" element={<HashList session={session.data} />} />
          <Route path="/engines/exceptions" element={<Exceptions session={session.data} />} />
          <Route path="/engines" element={<Engines session={session.data} />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes></Suspense>
  </main></div>
}

createRoot(document.getElementById('root')!).render(
  <QueryClientProvider client={client}><BrowserRouter basename="/console"><App /></BrowserRouter></QueryClientProvider>,
)
