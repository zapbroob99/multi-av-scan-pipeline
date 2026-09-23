import * as Primitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'

export function Dialog({ open, onOpenChange, title, description, children, className = '', locked = false }: {
  open: boolean; onOpenChange: (open: boolean) => void; title: string; description: string; children: ReactNode; className?: string; locked?: boolean
}) {
  return <Primitive.Root open={open} onOpenChange={onOpenChange}>
    <Primitive.Portal><Primitive.Overlay className="dialog-overlay" />
      <Primitive.Content className={`dialog-content ${className}`} onEscapeKeyDown={event => { if (locked) event.preventDefault() }} onInteractOutside={event => { if (locked) event.preventDefault() }}>
        <Primitive.Title className="dialog-title">{title}</Primitive.Title>
        <Primitive.Description className="muted">{description}</Primitive.Description>
        <Primitive.Close className="dialog-close" aria-label="Close dialog" disabled={locked}><X size={20} /></Primitive.Close>
        {children}
      </Primitive.Content>
    </Primitive.Portal>
  </Primitive.Root>
}
