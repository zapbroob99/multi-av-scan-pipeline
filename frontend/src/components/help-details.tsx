import type { ReactNode } from 'react'

/** General operating notes; actionable warnings stay outside this disclosure. */
export function HelpDetails({ title, children }: { title: string; children: ReactNode }) {
  return <details className="help-details"><summary>{title}</summary><div>{children}</div></details>
}
