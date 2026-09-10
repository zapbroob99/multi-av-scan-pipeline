import type { ComponentProps } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '../../lib/utils'

const buttonVariants = cva('button', { variants: { variant: {
  default: 'button-primary', secondary: 'button-secondary', destructive: 'button-danger',
}}, defaultVariants: { variant: 'default' } })

export function Button({ className, variant, ...props }: ComponentProps<'button'> & VariantProps<typeof buttonVariants>) {
  return <button className={cn(buttonVariants({ variant }), className)} {...props} />
}
