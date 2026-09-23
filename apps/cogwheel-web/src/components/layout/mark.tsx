/**
 * Cogwheel's mark.
 *
 * The same ten-rectangle path as `docs/assets/logo.svg`, which is the master and whose comment
 * explains the geometry: filled rectangles on an even grid rather than a stroked glyph, because a
 * 2px stroke is the first thing to break when a mark is scaled to 16px.
 *
 * Inlined rather than loaded through an `<img>` on purpose. `fill="currentColor"` only resolves
 * when the SVG is part of the document; through an `<img>` it falls back to the file's own
 * default and stops following the text beside it, and the design contract has no brand hue — the
 * mark is black on paper and white on ink, and it gets there by inheriting.
 *
 * Six files carry this path and have to move together: this component,
 * `apps/cogwheel-web/index.html`'s `<link rel="icon">` data URI, `deploy/unraid/cogwheel.svg`,
 * and the three `docs/assets/logo*.svg`.
 */
export function Mark({ className }: { className?: string }) {
  return (
    <svg aria-hidden className={className} fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
      <path d="M10 2h4v2h-4zM6 4h12v2H6zM4 6h16v2H4zM4 8h4v8H4zM16 8h4v8h-4zM2 10h2v4H2zM20 10h2v4h-2zM4 16h16v2H4zM6 18h12v2H6zM10 20h4v2h-4z" />
    </svg>
  );
}
