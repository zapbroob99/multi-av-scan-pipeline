import type { FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Search, X } from 'lucide-react'
import { Button } from './ui/button'

/** Name search for inventory lists. The query lives in the URL as ``q`` and a
 * new search always starts from the first page, so the cursor never points
 * into a different result set. */
export function ListSearch({ label, placeholder }: { label: string; placeholder: string }) {
  const [params, setParams] = useSearchParams()
  const current = params.get('q') || ''
  function apply(value: string) {
    const next = new URLSearchParams(params)
    next.delete('after')
    if (value.trim()) next.set('q', value.trim()); else next.delete('q')
    setParams(next)
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    apply(String(new FormData(event.currentTarget).get('q') || ''))
  }
  return <form key={current} className="list-search" role="search" aria-label={label} onSubmit={submit}>
    <label className="search"><Search size={16} aria-hidden="true" />
      <input name="q" aria-label={label} placeholder={placeholder} maxLength={100} defaultValue={current} /></label>
    <Button variant="secondary" type="submit">Search</Button>
    {current && <Button variant="secondary" type="button" onClick={() => apply('')}><X size={14} aria-hidden="true" />Clear</Button>}
  </form>
}

/** Query parameters for a searchable list read. */
export function listQuery(after: string, q: string) {
  return new URLSearchParams({ limit: '20', ...(after ? { after } : {}), ...(q ? { q } : {}) })
}
