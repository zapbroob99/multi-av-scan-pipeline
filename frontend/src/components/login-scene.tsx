import { useEffect, useRef } from 'react'
import earthrise, { meta } from './login-art/earthrise'

/** Dot radius for each halftone step, as a fraction of a cell, so a dot's area
 * roughly matches the piece's coverage for that step (·, •, ●). */
const RADIUS = [0, 0.27, 0.38, 0.48]
const STEP: Record<string, number> = { '·': 1, '•': 2, '●': 3 }
const STILL_AT = 6
/** The Earth's centre column, placed right of centre the way the piece frames it. */
const FOCUS = { col: 141.5, at: 0.68 }

/** Scale the scene to cover a box, the way background-size: cover does. Rows are
 * centred; columns put `focus.col` at `focus.at` of the width (centred without
 * one), never leaving a gap at either edge. */
export function coverLayout(width: number, height: number, focus?: { col: number; at: number }, cols = meta.cols, rows = meta.rows) {
  const cell = Math.max(width / cols, height / rows)
  const centred = (width - cols * cell) / 2
  const left = focus ? Math.min(0, Math.max(width - cols * cell, width * focus.at - focus.col * cell)) : centred
  return { cell, left, top: (height - rows * cell) / 2 }
}

/** The "earthrise" ASCII scene (MIT, bas3line/ascii) behind the sign-in form.
 * Decorative only: hidden from assistive technology, drawn on wide screens only,
 * a single still frame when the operator asks for reduced motion, and paused by
 * the browser whenever the tab is hidden. It is unmounted once signed in. */
export function LoginScene() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || typeof window.matchMedia !== 'function' || !window.matchMedia('(min-width: 801px)').matches) return
    let context: CanvasRenderingContext2D | null = null
    try { context = canvas.getContext('2d') } catch { return }
    if (!context) return
    const ctx = context
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const color = new Uint8Array(meta.cols * meta.rows)
    let frame: ((t: number, env?: { color?: Uint8Array }) => string) | null = null
    let raf = 0, last = -Infinity, started = 0, disposed = false

    function size() {
      const box = canvas!.getBoundingClientRect(), ratio = Math.min(window.devicePixelRatio || 1, 2)
      canvas!.width = Math.max(1, Math.round(box.width * ratio))
      canvas!.height = Math.max(1, Math.round(box.height * ratio))
    }
    function draw(t: number) {
      if (!frame) return
      const text = frame(t, { color })
      const { cell, left, top } = coverLayout(canvas!.width, canvas!.height, FOCUS)
      ctx.fillStyle = meta.ground
      ctx.fillRect(0, 0, canvas!.width, canvas!.height)
      // One path per palette colour keeps the fill-style changes to a few dozen a frame.
      const paths = new Map<number, Path2D>()
      for (let r = 0; r < meta.rows; r++) {
        const y = top + (r + 0.5) * cell
        if (y < -cell || y > canvas!.height + cell) continue
        for (let x = 0; x < meta.cols; x++) {
          const step = STEP[text[r * (meta.cols + 1) + x]]
          if (!step) continue
          const cx = left + (x + 0.5) * cell
          if (cx < -cell || cx > canvas!.width + cell) continue
          const index = color[r * meta.cols + x]
          let path = paths.get(index)
          if (!path) paths.set(index, path = new Path2D())
          const radius = RADIUS[step] * cell
          path.moveTo(cx + radius, y)
          path.arc(cx, y, radius, 0, Math.PI * 2)
        }
      }
      for (const [index, path] of paths) { ctx.fillStyle = meta.palette[index]; ctx.fill(path) }
    }
    function tick(now: number) {
      if (disposed) return
      raf = requestAnimationFrame(tick)
      if (now - last < 1000 / meta.fps) return
      last = now
      draw((now - started) / 1000)
    }
    const observer = new ResizeObserver(() => { size(); if (still) draw(STILL_AT) })
    size()
    // Building the scene's fixed fields takes a moment: let the form paint and
    // take focus first.
    const timer = window.setTimeout(() => {
      if (disposed) return
      frame = earthrise()
      observer.observe(canvas)
      if (still) draw(STILL_AT)
      else { started = performance.now(); raf = requestAnimationFrame(tick) }
    }, 60)
    return () => { disposed = true; window.clearTimeout(timer); cancelAnimationFrame(raf); observer.disconnect() }
  }, [])
  return <canvas ref={canvasRef} className="login-scene" aria-hidden="true" />
}
