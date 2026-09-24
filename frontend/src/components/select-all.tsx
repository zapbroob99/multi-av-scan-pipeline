import { useEffect, useRef } from 'react'

/** Header checkbox for a page of selectable rows.
 *
 * Selects every selectable row on the current page (callers exclude active or
 * protected rows and cap the list at the bulk-action limit), clears them when
 * all are already selected, and shows the mixed state for a partial selection.
 * It never reaches beyond the rows the operator can see. */
export function SelectAllCheckbox({ selectable, selected, onChange, disabled = false, label = 'Select all on this page' }: {
  selectable: number[]; selected: number[]; onChange: (ids: number[]) => void; disabled?: boolean; label?: string
}) {
  const box = useRef<HTMLInputElement>(null)
  const chosen = selectable.filter(id => selected.includes(id)).length
  const all = selectable.length > 0 && chosen === selectable.length
  useEffect(() => { if (box.current) box.current.indeterminate = chosen > 0 && !all }, [chosen, all])
  return <input ref={box} type="checkbox" aria-label={label} checked={all}
    disabled={disabled || selectable.length === 0} onChange={() => onChange(all ? [] : selectable)} />
}
