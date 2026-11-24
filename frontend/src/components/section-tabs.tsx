import { useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Button } from './ui/button'

/** Explicit back control: several detail pages could only be left with the
 * browser's own back button. Falls back to a known route when this page was
 * opened directly, so the control never dead-ends. */
export function BackLink({ to, label = 'Back' }: { to: string; label?: string }) {
  const navigate = useNavigate()
  return <Button variant="secondary" className="back-link" onClick={() => {
    if (window.history.length > 1) navigate(-1)
    else navigate(to)
  }}><ArrowLeft size={16} />{label}</Button>
}
