/**
 * The MASP mark drawn inline so it follows the active theme: tile and glyph
 * colours come from CSS tokens. public/favicon.svg is the same mark with the dark
 * theme's colours fixed, since a browser tab cannot read the console's tokens.
 */
export function BrandMark({ size, label }: { size: number; label?: string }) {
  return <svg className="brand-mark" width={size} height={size} viewBox="0 0 64 64"
    role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : true} focusable="false">
    <rect className="brand-mark-tile" x="0" y="0" width="64" height="64" rx="6" />
    <path className="brand-mark-glyph" d="M18 46V18h7.2L32 30.6 38.8 18H46v28h-7V29.2L33.7 38h-3.4L25 29.2V46z" />
  </svg>
}
