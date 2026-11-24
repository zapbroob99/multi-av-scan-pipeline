import { render } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { LoginScene } from './login-scene'

describe('Sign-in engraving', () => {
  it('keeps the decorative artwork outside the accessibility tree', () => {
    const { container } = render(<LoginScene />)
    expect(container.querySelector('.login-scene')).toHaveAttribute('aria-hidden', 'true')
    expect(container.querySelector('svg')).toHaveAttribute('focusable', 'false')
  })
})
