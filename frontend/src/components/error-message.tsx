import { useState } from 'react'
import { Button } from './ui/button'

/** Works for query errors and form receipts which preserve only Error.message. */
export function ErrorMessage({ message }: { message: string }) {
  const reference = /\[Request ID: ([A-Za-z0-9._:/-]{1,128})\]/.exec(message)
  const [copied, setCopied] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)
  return <>{message}{reference && <span className="error-reference">
    <Button type="button" variant="secondary" onClick={async () => {
      try { await navigator.clipboard.writeText(reference[1]); setCopied(reference[1]); setFailed(false) }
      catch { setFailed(true) }
    }}>{copied === reference[1] ? 'Request ID copied' : 'Copy request ID'}</Button>
    {failed && <span>Copy unavailable. Select the request ID in the message to copy it.</span>}
  </span>}</>
}
