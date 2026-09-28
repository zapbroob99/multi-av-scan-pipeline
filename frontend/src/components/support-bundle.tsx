import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { request, type Session } from '../lib/api'
import { Button } from './ui/button'
import { Dialog } from './ui/dialog'
import { ErrorMessage } from './error-message'

/** Admin download of the support bundle; recorded in the audit trail. */
export function SupportBundleButton({ session }: { session: Session }) {
  const [open, setOpen] = useState(false)
  const bundle = useMutation({ retry: false,
    mutationFn: () => request('/api/ui/v1/system/support-bundle', 'post', { csrf: session.csrf_token }),
    onSuccess: file => {
      const url = URL.createObjectURL(new Blob([file.content], { type: `${file.media_type};charset=utf-8` }))
      const anchor = document.createElement('a')
      try {
        anchor.href = url; anchor.download = file.filename; document.body.append(anchor); anchor.click()
      } finally { anchor.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 1000) }
      setOpen(false)
    } })
  return <>
    <Button variant="secondary" onClick={() => { bundle.reset(); setOpen(true) }}><Download size={14} aria-hidden="true" />Support bundle</Button>
    <Dialog open={open} onOpenChange={value => { if (!bundle.isPending) setOpen(value) }} title="Download a support bundle?"
      description="One JSON file with versions, the health report, configuration, worker and engine state, recent engine errors and recent administrative actions.">
      <ul className="bundle-contents">
        <li><strong>Left out:</strong> passwords, tokens and keys; sample content, filenames and hashes; console users' addresses.</li>
        <li><strong>Included:</strong> configuration values such as host names, paths and IP allowlists. Review the file before sharing it outside your institution.</li>
        <li>The download is recorded in the audit trail.</li>
      </ul>
      {bundle.error && <p role="alert" className="error"><ErrorMessage message={bundle.error.message || ''} /></p>}
      <div className="dialog-actions"><Button variant="secondary" disabled={bundle.isPending} onClick={() => setOpen(false)}>Cancel</Button>
        <Button disabled={bundle.isPending} onClick={() => bundle.mutate()}>{bundle.isPending ? 'Preparing…' : 'Download'}</Button></div>
    </Dialog>
  </>
}
