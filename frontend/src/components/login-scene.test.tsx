import { render } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { LoginScene, coverLayout } from './login-scene'

describe('Sign-in scene', () => {
  it('covers its box the way background-size: cover does, centred', () => {
    // Wider than 2:1: the width decides and rows are cropped top and bottom.
    expect(coverLayout(1000, 300)).toEqual({ cell: 5, left: 0, top: -100 })
    // Taller than 2:1: the height decides and columns are cropped at the sides.
    expect(coverLayout(800, 720)).toEqual({ cell: 7.2, left: -320, top: 0 })
  })
  it('keeps a focus column at its place across the width, without leaving an edge bare', () => {
    // Column 100 of the 1440 px-wide scene at 75% of an 800 px box.
    expect(coverLayout(800, 720, { col: 100, at: 0.75 })).toEqual({ cell: 7.2, left: 600 - 720, top: 0 })
    // A focus that would pull the scene past either edge is clamped to it.
    expect(coverLayout(800, 720, { col: 199, at: 0.1 }).left).toBe(800 - 1440)
    expect(coverLayout(800, 720, { col: 1, at: 0.9 }).left).toBe(0)
  })
  it('is decorative and does nothing where it cannot draw', () => {
    // jsdom has neither matchMedia nor a 2D canvas: the component must stay inert.
    const { container } = render(<LoginScene />)
    const canvas = container.querySelector('canvas')!
    expect(canvas).toHaveAttribute('aria-hidden', 'true')
    expect(canvas).toHaveClass('login-scene')
  })
})
