/** One task map drives the rail, section navigation and location trail. */
export type NavigationItem = { to: string; label: string; admin?: boolean; prefixes?: string[] }
export type NavigationArea = { id: string; label: string; admin?: boolean; items: NavigationItem[] }
export const NAVIGATION: NavigationArea[] = [
  { id: 'scans', label: 'Scans', items: [
    { to: '/dashboard', label: 'Manual scans', prefixes: ['/scans/', '/batches/', '/files/'] },
    { to: '/api-ledger', label: 'Integration scans' },
    { to: '/scans/new', label: 'Submit sample' },
    { to: '/hash-scan', label: 'Hash lookup' },
  ] },
  { id: 'integrations', label: 'Integrations', admin: true, items: [
    { to: '/service-clients', label: 'Connected systems' },
    { to: '/integrations/gateways', label: 'ICAP gateways' },
  ] },
  { id: 'storage', label: 'Storage', items: [
    { to: '/storage', label: 'Watched folders', prefixes: ['/storage/locations/'] },
    { to: '/storage/access', label: 'Sources & access', admin: true },
    { to: '/storage/intake', label: 'File intake', admin: true },
    { to: '/storage/findings', label: 'Folder findings' },
  ] },
  { id: 'policies', label: 'Policies', admin: true, items: [
    { to: '/policies/profiles', label: 'Scan profiles' },
    { to: '/engines/hash-list', label: 'Hash list' },
    { to: '/engines/exceptions', label: 'File exceptions' },
  ] },
  { id: 'infrastructure', label: 'Scan infrastructure', admin: true, items: [
    { to: '/system/overview', label: 'Health & overview' },
    { to: '/engines', label: 'Engines' },
    { to: '/system', label: 'Workers' },
    { to: '/system/pools', label: 'Worker groups' },
    { to: '/system/runtime', label: 'Runtime & queue' },
  ] },
  { id: 'administration', label: 'Administration', admin: true, items: [
    { to: '/users', label: 'Operators' },
    { to: '/scan-policy', label: 'Limits & API behavior' },
    { to: '/administration/notifications', label: 'Notifications' },
    { to: '/system/retention', label: 'Retention & cleanup' },
    { to: '/audit', label: 'Audit trail' },
  ] },
]

export function navigationFor(path: string) {
  if (path === '/system/delivery') return null // Ambiguous former page: choose its new task destination.
  for (const area of NAVIGATION) {
    const item = area.items.find(item => item.to === path)
    if (item) return { area, item }
  }
  const candidates = NAVIGATION.flatMap(area => area.items.flatMap(item => [item.to + '/', ...(item.prefixes ?? [])]
    .filter(prefix => path.startsWith(prefix)).map(prefix => ({ area, item, length: prefix.length }))))
  return candidates.sort((a, b) => b.length - a.length)[0] ?? null
}

export function visibleNavigation(admin: boolean) {
  return NAVIGATION.filter(area => admin || !area.admin).map(area => ({ ...area, items: area.items.filter(item => admin || !item.admin) }))
}

export function locationTrail(path: string): [string, string] {
  if (path === '/assistant') return ['Help', 'Aselix AI']
  if (path === '/account') return ['Personal', 'Account']
  if (path === '/about') return ['Personal', 'About']
  if (path === '/system/delivery') return ['Help', 'Connection and delivery monitoring']
  if (path === '/configuration') return ['Help', 'Configuration guide']
  const match = navigationFor(path)
  return match ? [match.area.label, match.item.label] : ['MASP', 'Workspace']
}
