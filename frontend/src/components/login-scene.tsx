/** An original full-bleed contour field, like fine lines draped over fabric.
 * Deterministic SVG geometry; no lettering, remote assets or animation. */
const CONTOURS = Array.from({ length: 166 }, (_, row) => {
  const base = -700 + row * 14
  return Array.from({ length: 231 }, (_, column) => {
    const along = -700 + column * 10
    const ridge = Math.exp(-(((along - 480) / 420) ** 2))
    const x = along + 30 * Math.sin(base / 260) * ridge
    const y = base + 195 * ridge * Math.sin(along / 260 + base / 310)
      + 54 * Math.sin(along / 170 - base / 460)
    return `${column ? 'L' : 'M'}${x.toFixed(2)},${y.toFixed(2)}`
  }).join(' ')
})

export function LoginScene() {
  return <div className="login-scene" aria-hidden="true">
    <svg className="login-engraving" viewBox="0 0 900 940" preserveAspectRatio="xMidYMid slice" fill="none" focusable="false">
      <g className="login-filaments" transform="rotate(-28 450 470)">
        {CONTOURS.map((d, index) => <path key={index} d={d} />)}
      </g>
    </svg>
  </div>
}
