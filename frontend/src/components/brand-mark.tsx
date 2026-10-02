/**
 * The MASP mark drawn inline so it follows the active theme. The favicon keeps
 * its fixed dark tile for browser tabs; inside the console a dark square on the
 * light theme reads as a hole, so tile and glyph colours come from CSS tokens.
 */
export function BrandMark({ size, label }: { size: number; label?: string }) {
  return <svg className="brand-mark" width={size} height={size} viewBox="0 0 64 64"
    role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : true} focusable="false">
    <rect className="brand-mark-tile" x="0" y="0" width="64" height="64" rx="6" />
    <path className="brand-mark-glyph" d="M18 46V18h7.2L32 30.6 38.8 18H46v28h-7V29.2L33.7 38h-3.4L25 29.2V46z" />
  </svg>
}
