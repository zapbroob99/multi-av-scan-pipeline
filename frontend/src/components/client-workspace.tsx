import { createContext, useContext, useEffect, type ReactNode } from 'react'
import { Link } from 'react-router-dom'

export type ClientTab = 'settings' | 'setup' | 'profiles' | 'storage' | 'credentials'
export const ClientWorkspace = createContext<{
  clientId: number
  tab: ClientTab
  select: (tab: ClientTab) => void
  guard: (panel: string, blocked: boolean) => void
} | null>(null)

export function useClientPanelGuard(panel: string, blocked: boolean) {
  const workspace = useContext(ClientWorkspace)
  const guard = workspace?.guard
  useEffect(() => {
    guard?.(panel, blocked)
    return () => guard?.(panel, false)
  }, [guard, panel, blocked])
  return workspace
}

export function ClientPanelLink({ clientId, tab, children, className }: {
  clientId: number | string; tab: ClientTab; children: ReactNode; className?: string
}) {
  const workspace = useContext(ClientWorkspace)
  return workspace
    ? <button type="button" className={className || 'client-inline-link'} onClick={() => workspace.select(tab)}>{children}</button>
    : <Link className={className} to={tab === 'settings' ? '/service-clients' : `/service-clients/${clientId}/${tab}`}>{children}</Link>
}
