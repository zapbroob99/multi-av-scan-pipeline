import { ArrowLeft, Cable, Database, GitBranch, KeyRound } from 'lucide-react'
import { Link, NavLink } from 'react-router-dom'
import { useContext } from 'react'
import { ClientWorkspace } from './client-workspace'

export function ClientNavigation({ clientId }: { clientId: number | string }) {
  const workspace = useContext(ClientWorkspace)
  if (workspace) return null
  return <nav className="client-navigation" aria-label="Client navigation">
    <Link className="client-back" to="/service-clients"><ArrowLeft size={15} aria-hidden="true" />All connected systems</Link>
    <div className="client-tabs">
      <NavLink to={`/service-clients/${clientId}/overview`}><Cable size={16} aria-hidden="true" />Overview</NavLink>
      <NavLink to={`/service-clients/${clientId}/setup`}><Cable size={16} aria-hidden="true" />Connection</NavLink>
      <NavLink to={`/policies/profiles/${clientId}`}><GitBranch size={16} aria-hidden="true" />Scan profiles</NavLink>
      <NavLink to={`/storage/access/${clientId}`}><Database size={16} aria-hidden="true" />Sources &amp; access</NavLink>
      <NavLink to={`/service-clients/${clientId}/credentials`}><KeyRound size={16} aria-hidden="true" />Credentials</NavLink>
    </div>
  </nav>
}
