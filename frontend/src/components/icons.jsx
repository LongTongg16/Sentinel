// Inline stroke icons (24x24, currentColor) so status cues are real SVG rather
// than text glyphs, plus the two Sentinel identity marks. Every icon here is
// decorative: callers always pair it with a visible text label, so each renders
// aria-hidden and non-focusable. Size and colour come from the caller via
// className (e.g. "size-4 text-ink-dim").

function Svg({ children, className }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      focusable="false"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="2"
      viewBox="0 0 24 24"
    >
      {children}
    </svg>
  )
}

export function CheckIcon({ className }) {
  return (
    <Svg className={className}>
      <path d="M20 6 9 17l-5-5" />
    </Svg>
  )
}

export function MinusIcon({ className }) {
  return (
    <Svg className={className}>
      <path d="M5 12h14" />
    </Svg>
  )
}

export function InfoIcon({ className }) {
  return (
    <Svg className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </Svg>
  )
}

export function WarningIcon({ className }) {
  return (
    <Svg className={className}>
      <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
      <path d="M12 9v4M12 17h.01" />
    </Svg>
  )
}

export function CriticalIcon({ className }) {
  return (
    <Svg className={className}>
      <path d="M7.9 2h8.2L22 7.9v8.2L16.1 22H7.9L2 16.1V7.9L7.9 2Z" />
      <path d="M12 8v4M12 16h.01" />
    </Svg>
  )
}

export function HelpIcon({ className }) {
  return (
    <Svg className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01" />
    </Svg>
  )
}

export function SpinnerIcon({ className }) {
  return (
    <Svg className={className}>
      <path d="M12 3a9 9 0 1 0 9 9" />
    </Svg>
  )
}

export function ArrowRightIcon({ className }) {
  return (
    <Svg className={className}>
      <path d="M4 12h15M13 6l6 6-6 6" />
    </Svg>
  )
}

// Small crosshair - the compact form of the Sentinel mark.
export function TargetIcon({ className }) {
  return (
    <Svg className={className}>
      <circle cx="12" cy="12" r="7" />
      <path d="M12 1.5v4M12 18.5v4M1.5 12h4M18.5 12h4" />
      <circle cx="12" cy="12" r="1.6" />
    </Svg>
  )
}

// Certificate geometry - used only as the TLS scanner glyph.
export function CertificateIcon({ className }) {
  return (
    <Svg className={className}>
      <path d="M4 4h16v11H4z" />
      <path d="M8 8h8M8 11.5h5" />
      <path d="M12 15v3.5l-2.4-1.3L7.2 22V15" />
      <path d="M12 15v3.5l2.4-1.3L16.8 22V15" />
    </Svg>
  )
}

// Network-node geometry - used only as the HTTP scanner glyph.
export function NodesIcon({ className }) {
  return (
    <Svg className={className}>
      <circle cx="5" cy="6" r="2.4" />
      <circle cx="19" cy="12" r="2.4" />
      <circle cx="5" cy="18" r="2.4" />
      <path d="M7.1 7.3 16.9 10.8M16.9 13.2 7.1 16.7" />
    </Svg>
  )
}

// The full Sentinel reticle: rings, coordinate ticks, a slowly creeping
// dashed ring and one radar sweep. Purely an identity mark.
export function HeroReticle({ className }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      focusable="false"
      stroke="currentColor"
      viewBox="0 0 200 200"
    >
      <defs>
        <linearGradient
          gradientUnits="userSpaceOnUse"
          id="sentinel-sweep"
          x1="100"
          x2="196"
          y1="100"
          y2="100"
        >
          <stop offset="0" stopColor="#ffffff" stopOpacity="0.14" />
          <stop offset="1" stopColor="#ffffff" stopOpacity="0" />
        </linearGradient>
      </defs>
      <g className="radar-sweep">
        <path
          d="M100 100 196 100A96 96 0 0 0 148 16.9Z"
          fill="url(#sentinel-sweep)"
          stroke="none"
        />
      </g>
      <circle cx="100" cy="100" r="96" strokeOpacity="0.16" />
      <circle cx="100" cy="100" r="66" strokeOpacity="0.12" />
      <circle cx="100" cy="100" r="34" strokeOpacity="0.2" />
      <circle
        className="spin-slow"
        cx="100"
        cy="100"
        r="81"
        strokeDasharray="2 10"
        strokeOpacity="0.3"
      />
      <path
        d="M100 2v26M100 172v26M2 100h26M172 100h26"
        strokeOpacity="0.34"
      />
      <path
        d="M100 90v20M90 100h20"
        strokeOpacity="0.55"
        strokeWidth="1.2"
      />
      <circle cx="100" cy="100" fill="currentColor" r="2.4" stroke="none" />
    </svg>
  )
}
