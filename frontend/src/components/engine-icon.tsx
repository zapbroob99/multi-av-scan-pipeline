import { Binary, Cpu, FileSearch, Globe, Hash, ScanSearch, ShieldCheck } from 'lucide-react'

/** Per-adapter icons so engines are told apart at a glance.
 *
 * Keyed on the adapter key the browser already receives, so adding an icon
 * needs no contract change. An unknown adapter keeps the generic chip icon
 * rather than disappearing. */
const ICONS: Record<string, typeof Cpu> = {
  clamav: ShieldCheck,
  microsoft_defender: ShieldCheck,
  yara: ScanSearch,
  virustotal: Globe,
  static_metadata: Binary,
  file_type: FileSearch,
  hash_list: Hash,
}

export function EngineIcon({ adapterKey, size = 23 }: { adapterKey: string; size?: number }) {
  const Icon = ICONS[adapterKey] || Cpu
  return <Icon size={size} aria-hidden="true" />
}
