export type MarkVariant = "full" | "compact" | "pixel"

interface MarkProps {
  size?: number
  variant?: MarkVariant
  className?: string
}

/**
 * Geometry copied from assets/brand/mark.svg, mark-compact.svg and mark-16.svg.
 * Colours are swapped for theme variables so the mark survives the dark theme:
 * the container keeps the accent, the cable/sling/seal keep the foreground,
 * the crate slats keep the background.
 */
export function Mark({ size = 40, variant = "full", className }: MarkProps) {
  const viewBox = variant === "pixel" ? "0 0 16 16" : "0 0 40 40"

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={viewBox}
      width={size}
      height={size}
      role="img"
      aria-label="sealift"
      className={className}
    >
      {variant === "full" ? <FullGeometry /> : null}
      {variant === "compact" ? <CompactGeometry /> : null}
      {variant === "pixel" ? <PixelGeometry /> : null}
    </svg>
  )
}

function FullGeometry() {
  return (
    <>
      <rect x="19.1" y="1" width="1.8" height="6" rx=".9" fill="var(--ink)" />
      <circle cx="20" cy="8.2" r="2" fill="none" stroke="var(--ink)" strokeWidth="1.8" />
      <path
        d="M7.5 17.5 L20 10.2 L32.5 17.5"
        fill="none"
        stroke="var(--ink)"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <rect x="4" y="17" width="32" height="19" rx="3" fill="var(--accent)" />
      <g fill="var(--background)" opacity=".38">
        <rect x="8.4" y="20.5" width="1.8" height="12" rx=".9" />
        <rect x="12.6" y="20.5" width="1.8" height="12" rx=".9" />
        <rect x="16.8" y="20.5" width="1.8" height="12" rx=".9" />
      </g>
      <path
        d="M27.50 20.60 Q28.67 19.85 29.52 20.96 Q30.88 20.65 31.29 21.98 Q32.67 22.16 32.61 23.55 Q33.84 24.19 33.31 25.48 Q34.25 26.50 33.31 27.52 Q33.84 28.81 32.61 29.45 Q32.67 30.84 31.29 31.02 Q30.88 32.35 29.52 32.04 Q28.67 33.15 27.50 32.40 Q26.33 33.15 25.48 32.04 Q24.12 32.35 23.71 31.02 Q22.33 30.84 22.39 29.45 Q21.16 28.81 21.69 27.52 Q20.75 26.50 21.69 25.48 Q21.16 24.19 22.39 23.55 Q22.33 22.16 23.71 21.98 Q24.12 20.65 25.48 20.96 Q26.33 19.85 27.50 20.60 Z"
        fill="var(--ink)"
      />
      <circle cx="27.5" cy="26.5" r="3.7" fill="none" stroke="var(--accent)" strokeWidth="1" />
    </>
  )
}

function CompactGeometry() {
  return (
    <>
      <rect x="18.4" y="0" width="3.2" height="7" rx="1.2" fill="var(--ink)" />
      <path
        d="M6.5 14 L20 6.2 L33.5 14"
        fill="none"
        stroke="var(--ink)"
        strokeWidth="3.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <rect x="2.5" y="13.5" width="35" height="24" rx="4.5" fill="var(--accent)" />
      <path
        d="M26.00 18.30 Q27.82 17.51 29.12 19.01 Q31.11 19.09 31.63 21.01 Q33.39 21.94 33.02 23.90 Q34.20 25.50 33.02 27.10 Q33.39 29.06 31.63 29.99 Q31.11 31.91 29.12 31.99 Q27.82 33.49 26.00 32.70 Q24.18 33.49 22.88 31.99 Q20.89 31.91 20.37 29.99 Q18.61 29.06 18.98 27.10 Q17.80 25.50 18.98 23.90 Q18.61 21.94 20.37 21.01 Q20.89 19.09 22.88 19.01 Q24.18 17.51 26.00 18.30 Z"
        fill="var(--ink)"
      />
    </>
  )
}

function PixelGeometry() {
  return (
    <>
      <rect x="7.25" y="0" width="1.5" height="3" fill="var(--ink)" />
      <path
        d="M2.2 6.6 L8 2.6 L13.8 6.6"
        fill="none"
        stroke="var(--ink)"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <rect x="0" y="6.5" width="16" height="9.5" rx="2" fill="var(--accent)" />
      <circle cx="10.5" cy="11.25" r="3.1" fill="var(--ink)" />
    </>
  )
}
