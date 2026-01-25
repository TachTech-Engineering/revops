interface PantherLogoProps {
  size?: number
  className?: string
}

export default function PantherLogo({ size = 32, className = '' }: PantherLogoProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <defs>
        <linearGradient id="panther-bg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#7c3aed" />
          <stop offset="100%" stopColor="#4c1d95" />
        </linearGradient>
      </defs>

      {/* Background hexagon */}
      <polygon
        points="32,2 58,17 58,47 32,62 6,47 6,17"
        fill="url(#panther-bg)"
      />

      {/* Fierce panther face - geometric shapes only */}
      <g fill="#c4b5fd">
        {/* Left ear - sharp triangle */}
        <polygon points="12,22 18,12 24,24" />
        {/* Right ear - sharp triangle */}
        <polygon points="52,22 46,12 40,24" />
      </g>

      {/* Head - angular hexagon shape */}
      <polygon
        points="32,18 46,26 46,40 38,50 26,50 18,40 18,26"
        fill="#c4b5fd"
      />

      {/* Snout - trapezoid */}
      <polygon points="26,42 38,42 42,52 22,52" fill="#a78bfa" />

      {/* Eyes - angry slanted parallelograms */}
      <polygon points="21,28 28,32 28,36 21,32" fill="#1e1b4b" />
      <polygon points="43,28 36,32 36,36 43,32" fill="#1e1b4b" />

      {/* Eye glints - small diamonds */}
      <polygon points="24,30 26,31 24,32 22,31" fill="#fef3c7" />
      <polygon points="40,30 38,31 40,32 42,31" fill="#fef3c7" />

      {/* Brow furrow - angular lines for fierce look */}
      <polygon points="20,25 29,29 29,27 22,24" fill="#7c3aed" />
      <polygon points="44,25 35,29 35,27 42,24" fill="#7c3aed" />

      {/* Nose - downward triangle */}
      <polygon points="32,44 28,40 36,40" fill="#4c1d95" />

      {/* Snarl lines - teeth showing */}
      <polygon points="24,48 28,46 28,48" fill="#f5f3ff" />
      <polygon points="40,48 36,46 36,48" fill="#f5f3ff" />
      <polygon points="30,50 32,47 34,50" fill="#f5f3ff" />

      {/* Whisker marks - sharp lines */}
      <polygon points="14,38 22,40 22,42 14,40" fill="#7c3aed" />
      <polygon points="50,38 42,40 42,42 50,40" fill="#7c3aed" />
      <polygon points="12,44 20,44 20,46 12,46" fill="#7c3aed" />
      <polygon points="52,44 44,44 44,46 52,46" fill="#7c3aed" />
    </svg>
  )
}
