import type { components } from '../lib/api.generated'

type Context = components['schemas']['ConfigurationContext']

/** Shared, collapsed provenance keeps the primary form readable. */
export function ConfigurationContext({ context, title = 'Scope and application' }: { context?: Context; title?: string }) {
  if (!context) return null
  return <div className="configuration-context">
    {context.state !== 'resolved' && <p role="status" className="callout">{context.note || `Configuration ${context.state}.`}</p>}
    <details><summary>{title}</summary>
      <dl><dt>Source</dt><dd>{context.source}</dd>
        <dt>Affects</dt><dd>{context.scope}</dd>
        <dt>Takes effect</dt><dd>{context.applies}</dd>
        <dt>Change at</dt><dd>{context.edit_at}</dd>
        <dt>Restart</dt><dd>{context.restart}</dd></dl>
      {context.state === 'resolved' && context.note && <p className="muted">{context.note}</p>}
    </details>
  </div>
}
