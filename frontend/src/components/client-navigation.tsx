import { ArrowLeft, Cable, Database, GitBranch, KeyRound } from 'lucide-react'
import { Link, NavLink } from 'react-router-dom'
import { useContext } from 'react'
import { ClientWorkspace } from './client-workspace'

export function ClientNavigation({ clientId }: { clientId: number | string }) {
  const workspace = useContext(ClientWorkspace)
  if (workspace) return null
  return <nav className="client-navigation" aria-label="Client navigation">
    <Link className="client-back" to="/service-clients"><ArrowLeft size={15} aria-hidden="true" />All service clients</Link>
    <div className="client-tabs">
      <NavLink to={`/service-clients/${clientId}/setup`}><Cable size={16} aria-hidden="true" />Connection</NavLink>
      <NavLink to={`/service-clients/${clientId}/profiles`}><GitBranch size={16} aria-hidden="true" />Profile routing</NavLink>
      <NavLink to={`/service-clients/${clientId}/storage`}><Database size={16} aria-hidden="true" />Storage</NavLink>
      <NavLink to={`/service-clients/${clientId}/credentials`}><KeyRound size={16} aria-hidden="true" />Credentials</NavLink>
    </div>
  </nav>
}
