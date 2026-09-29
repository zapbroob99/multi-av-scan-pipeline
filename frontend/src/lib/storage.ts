import type { components } from './api.generated'

type Schemas = components['schemas']
export type StorageOverview = Schemas['StorageOverview']
export type LocationSummary = Schemas['LocationSummary']
export type LocationDetail = Schemas['LocationDetail']
export type StorageObject = Schemas['StorageObject']
export type StorageFinding = Schemas['StorageFinding']
export type StoragePolicy = Schemas['StoragePolicy']
export type StorageOptions = Schemas['StorageOptions']
export type ObjectState = StorageObject['state']

/** Every state is shown as what it means. "Type check passed" is deliberately
 * not "clean": the light tier never ran an antivirus engine. */
export const STATE_LABELS: Record<ObjectState, string> = {
  waiting: 'Waiting to settle',
  changed: 'Changed, waiting to settle',
  light_passed: 'Type check passed (not antivirus scanned)',
  light_detected: 'Detected by light inspection',
  full_pending: 'Awaiting full scan',
  unreadable: 'Unreadable',
  removed: 'Removed',
}

export const STATE_ORDER: ObjectState[] = ['light_detected', 'full_pending', 'light_passed', 'waiting', 'changed', 'unreadable', 'removed']

export const KIND_LABELS: Record<StorageFinding['kind'], string> = {
  type_policy: 'Content type not permitted',
  type_mismatch: 'Extension does not match content',
  archive_policy: 'Archive not permitted',
  hash_block: 'Hash on blocklist',
}

export const FAMILY_LABELS: Record<string, string> = {
  executable: 'Executables (PE, ELF, Mach-O, Java class, shortcut)',
  script: 'Scripts (by extension or #! header)',
  archive: 'Archives (zip, 7z, rar, gzip, tar, cab)',
  office: 'Office documents (OOXML, legacy Office, RTF)',
  pdf: 'PDF',
  image: 'Images (PNG, JPEG, GIF, BMP)',
  markup: 'XML',
  unrecognized: 'Unrecognized (plain text, CSV, other data)',
}

export function formatBytes(value: number) {
  if (value < 1024) return `${value} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let size = value / 1024, unit = 0
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1 }
  return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`
}

export function locationPath(location: { backend_key: string; prefix: string }) {
  return `${location.backend_key}:/${location.prefix}`
}
