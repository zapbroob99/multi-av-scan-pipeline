import { Link } from 'react-router-dom'
import type { Session } from '../lib/api'
import ScanPolicy from './scan-policy'
import Delivery from './delivery'

export default function NotificationSettings({ session }: { session: Session }) {
  return <section className="page management-page">
    <div className="page-heading"><div><h1>Notifications</h1>
      <p className="muted">Scan event selection and SIEM delivery. Webhook destinations and worker deployment are managed on the server.</p></div></div>
    <p className="callout">Folder findings use a separate notification queue, not included in the delivery counts below. <Link to="/storage/findings">View folder findings</Link>.</p>
    <ScanPolicy session={session} area="notifications" embedded />
    <Delivery session={session} section="notifications" embedded />
  </section>
}
