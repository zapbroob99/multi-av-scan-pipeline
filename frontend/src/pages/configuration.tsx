import { Link } from 'react-router-dom'

const TASKS = [
  { title: 'Connect an integration', text: 'Choose a client to follow its connection, profile, limits and engine routing.', scope: 'Per client · new submissions',
    links: [['/service-clients', 'Choose a client'], ['/service-clients/new', 'Create a service client']] },
  { title: 'Change file handling', text: 'Edit ordered rules on a client profile. Hash allowlist entries are informational; exact-file exceptions change the decision.', scope: 'Client profiles and security policy',
    links: [['/policies/profiles', 'Choose a connected system and profile'], ['/engines/hash-list', 'Manage hash list'], ['/engines/exceptions', 'Manage exceptions']] },
  { title: 'Configure scan capacity', text: 'Configure named engines, assign worker pools and inspect worker lifecycle and recorded health.', scope: 'Scan infrastructure · subsequent work',
    links: [['/engines', 'Manage engines'], ['/system', 'Inspect worker nodes'], ['/system/pools', 'Manage worker pools']] },
  { title: 'Connect storage', text: 'Choose a client to manage storage grants and watched folders. Backend roots and mounts are configured on the deployment.', scope: 'Client access and folder discovery',
    links: [['/storage/access', 'Manage sources and access'], ['/storage', 'Inspect folder scanning'], ['/storage/intake', 'Inspect file intake']] },
  { title: 'Set limits and notifications', text: 'Set API upload policy, response timing and SIEM event selection. Inspect ICAP limits and notification delivery separately.', scope: 'Global policy and reported service state',
    links: [['/scan-policy', 'Edit limits and API behavior'], ['/administration/notifications', 'Manage notifications'], ['/integrations/gateways', 'Inspect ICAP gateways']] },
  { title: 'Manage retention', text: 'Review the deployment retention policy and confirm eligible records before cleanup. The retention period is deployment-managed.', scope: 'Deployment policy and explicit deletion',
    links: [['/system/retention', 'Review retention cleanup']] },
  { title: 'Manage operator access', text: 'Manage local operators and inspect the recorded administrative audit trail. Directory accounts follow directory policy.', scope: 'Operator accounts and audit',
    links: [['/users', 'Manage users'], ['/audit', 'Inspect audit trail']] },
]

export default function Configuration() {
  return <section className="page management-page">
    <div className="page-heading"><div><h1>Configuration guide</h1><p className="muted">Start with the task. Each link opens the existing editor or a read-only status view.</p></div></div>
    <div className="configuration-hub">{TASKS.map(task => <section className="settings-panel" key={task.title}>
      <div className="settings-panel-header"><h2>{task.title}</h2></div>
      <div className="configuration-task-body"><p>{task.text}</p><p className="muted">{task.scope}</p>
        <ul>{task.links.map(([to, label]) => <li key={to}><Link to={to}>{label}</Link></li>)}</ul></div>
    </section>)}</div>
    <section className="settings-panel"><div className="settings-panel-header"><h2>Where settings take effect</h2></div>
      <div className="configuration-task-body"><dl className="report-metadata">
        <dt>Client rules</dt><dd>Apply to newly accepted files. Existing scans keep their recorded routing.</dd>
        <dt>Console limits</dt><dd>Runtime policy overrides apply without restarting. The separate deployment HTTP body ceiling still applies.</dd>
        <dt>Deployment settings</dt><dd>ICAP startup settings, storage roots, database/webhook secrets and retention period are configured outside this console. Recreate/restart the relevant service after a deployment change.</dd>
        <dt>Recorded checks</dt><dd>Configuration, heartbeat and health are different observations. Use the client's Overview to inspect their sources and freshness.</dd>
      </dl></div>
    </section>
  </section>
}
