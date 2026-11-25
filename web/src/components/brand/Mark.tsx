import { useId } from "react"

interface MarkProps {
  size?: number
  className?: string
}

/**
 * sealift's seal lifting a crate: the 16 unit drawing below 48 px, where the pier and the spots
 * would blur, and the full drawing from 48 px up. The seal and the hook take currentColor; the
 * crate takes --sealift-teal, which theme.css lightens in the dark theme.
 */
export function Mark({ size = 40, className }: MarkProps) {
  const small = size < 48
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={small ? "0 0 16 16" : "0 0 256 256"}
      width={size}
      height={size}
      role="img"
      aria-label="sealift"
      className={className}
    >
      {small ? <SmallGeometry /> : <FullGeometry />}
    </svg>
  )
}

function SmallGeometry() {
  return (
    <>
      <path fill="none" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" d="M7.5 1v1c0 .5-1.625.5-1.625 1.3a1.5625 1.325 0 0 0 3.125 0" />
      <path fill="currentColor" fillRule="evenodd" d="M.5 9.5C1.5 9.15 2.45 9.4 3 10c.25-.85 1-1.45 2-1.5-.05.9-.5 1.55-1.15 2.05C4 11 4.65 11 5.25 10.55 6.1 9.95 7 10 9 10c.8 0 1.15-.6 1.45-1.4.6-1.65 2.15-2.1 3.35-1.05.35.3.6.4.95.2.55-.3 1.05.2.75.8.2.8-.4 1.5-1.25 1.9-.6.3-.95.9-1 1.55 0 .7 1.75.65 1.75 1.5 0 .35-.55.5-1.25.5h-1.6c-.65 0-.8-.2-.65-.55-.7.6-1.45.9-2.25.85-.55 0-.9-.1-1.05-.3H5c-1.65 0-2.6-.9-3.2-2.25C.95 11.45.5 10.75.5 9.5zm10.65-.1a.48.48 0 0 0 .9.35c.25-.65.8-.8 1.25-.35a.48.48 0 0 0 .7-.65c-.9-.9-2.35-.6-2.85.65z" />
      <path fill="var(--sealift-teal,#0e7490)" fillRule="evenodd" d="M5 6h5v5H5zm1 1v2.2L8.2 7zm.8 3H9V7.8z" />
    </>
  )
}

function FullGeometry() {
  // Each mark on a page needs its own mask id, or the second one borrows the first one's mask.
  const maskId = `sealift-cutouts-${useId().replace(/:/g, "")}`
  return (
    <>
      <defs>
        <mask id={maskId} maskUnits="userSpaceOnUse" x="0" y="0" width="256" height="256">
          <path fill="#fff" d="M0 0h256v256H0z" />
          <path fill="none" stroke="#000" strokeLinecap="round" strokeWidth="3" d="M197 128c1-5.5 8-7.5 11-2.5m1 11c5-4 11-6 17-5" />
          <path d="M211 142c3-4.5 9-8 15-8-5 2-9 5-13 9.5-.9 1-2.8-.3-2-1.5zm7 2c2-3 5.2-6.1 9.3-7.5-3 2.4-5.3 5.1-7.1 8.6-.6 1.2-3.1.2-2.2-1.1z" />
          <path d="M48 192c10 3 21 3 37 3h59c2-5 9-10 19-12-6 4-16 8-16 13 0 3 8 3 17 1 12-3 18-10 20-17 .5-2 3-1 2.5 1-2 11-12 17-23 19-9 2-17 2-19-2H84c-18 0-27-1-36-4zm162-14c-3 7-7 13-15 17h26c5 0 8 0 9-2v3c-2 2-5 2-10 2h-33c9-4 16-12 21-22z" />
          <ellipse cx="128" cy="42" rx="3.9" ry="3.9" />
          <path d="M72 173c-1-3 8-6 9-3 2 3-8 7-9 3zm9 7c-1-3 7-6 8-3 2 3-7 6-8 3zm8-9c-1-3 9-6 10-3 2 4-9 7-10 3zm-25 10c-1-2 5-4 6-2 1 2-5 5-6 2z" />
        </mask>
      </defs>
      <g fill="currentColor" mask={`url(#${maskId})`}>
        <path d="M117 9h5v23h12V9h5v23h2a1 1 0 0 1 1 1v12a2 2 0 0 1-.7 1.5l-7 6a2 2 0 0 1-1.3.5h-1v4c0 5-2 7-6 9-3 2-5 4-5 7a7.5 7.5 0 0 0 15 0 2.6 2.6 0 0 1 5.2 0 14.3 14.3 0 0 1-28.6 0c0-6 4-10 8-13 2-1 3-2 3-4v-3h-1a2 2 0 0 1-1.3-.5l-7-6a2 2 0 0 1-.7-1.5V33a1 1 0 0 1 1-1h2z" />
        <path d="M15 148c9-3 19-2 25 4 2-7 10-12 18-13 2 0 2 2 2 4 0 7-3 11-7 16-5 6 3 13 10 9 7-4 15-13 30-15l61-2c9 0 14-5 18-15 7-18 26-28 41-15 2 2 5 2 8 2 4-5 12-1 10 5 2 7-3 15-11 19-8 4-10 13-13 22 2 5 4 8 10 10 9 4 14 8 14 12 0 4-7 5-14 5h-25l-24 1c-12 5-21 6-25 0H69c-15 0-23-6-29-18-3-6-3-10-9-12-10-3-16-8-18-16-.4-1.5.5-2.5 2-3z" />
        <path d="M13 196h230a3 3 0 0 1 3 3v6a3 3 0 0 1-3 3h-9v24a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2v-4l-20-20h-62v24a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2v-24H59l-20 20v4a2 2 0 0 1-2 2H24a2 2 0 0 1-2-2v-24h-9a3 3 0 0 1-3-3v-6a3 3 0 0 1 3-3zm26 12v12l12-12zm166 0 12 12v-12z" fillRule="evenodd" />
      </g>
      <path fill="var(--sealift-teal,#0e7490)" fillRule="evenodd" d="M92 90h12a1 1 0 0 1 1 1v2h44v-2a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1h-2v41h2a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H92a1 1 0 0 1-1-1v-10a1 1 0 0 1 1-1h2v-41h-2a1 1 0 0 1-1-1V91a1 1 0 0 1 1-1zm11 11v44h48v-44zm3 3h11v27l-11 10zm3 38 8-7.4v7.4zm11-38h13v12.5l-13 11.7zm0 28 13-11.5V142h-13zm16-28h10.8l-10.8 9.7zm0 13.8 12-10.8v35h-12z" />
    </>
  )
}
