interface RevOpsLogoProps {
  size?: number
  className?: string
}

export default function RevOpsLogo({ size = 32, className = '' }: RevOpsLogoProps) {
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
        <linearGradient id="revops-bg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#3b82f6" />
          <stop offset="100%" stopColor="#1e40af" />
        </linearGradient>
        <linearGradient id="revops-needle" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#f97316" />
          <stop offset="100%" stopColor="#ef4444" />
        </linearGradient>
        <linearGradient id="revops-redline" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#ef4444" />
          <stop offset="100%" stopColor="#dc2626" />
        </linearGradient>
      </defs>

      {/* Background circle */}
      <circle cx="32" cy="32" r="30" fill="url(#revops-bg)" />

      {/* Inner dark circle for gauge face */}
      <circle cx="32" cy="32" r="24" fill="#0f172a" />

      {/* Gauge arc background */}
      <path
        d="M 12 40 A 22 22 0 1 1 52 40"
        fill="none"
        stroke="#334155"
        strokeWidth="4"
        strokeLinecap="round"
      />

      {/* Redline zone (last 25% of arc) */}
      <path
        d="M 44 14.5 A 22 22 0 0 1 52 40"
        fill="none"
        stroke="url(#revops-redline)"
        strokeWidth="4"
        strokeLinecap="round"
      />

      {/* Active gauge fill */}
      <path
        d="M 12 40 A 22 22 0 0 1 44 14.5"
        fill="none"
        stroke="#22c55e"
        strokeWidth="4"
        strokeLinecap="round"
      />

      {/* Tick marks */}
      <g stroke="#64748b" strokeWidth="1.5">
        <line x1="12" y1="40" x2="16" y2="38" />
        <line x1="14" y1="28" x2="18" y2="30" />
        <line x1="22" y1="18" x2="25" y2="21" />
        <line x1="32" y1="14" x2="32" y2="18" />
        <line x1="42" y1="18" x2="39" y2="21" />
        <line x1="50" y1="28" x2="46" y2="30" />
        <line x1="52" y1="40" x2="48" y2="38" />
      </g>

      {/* Needle pointing to ~75% (high performance) */}
      <g transform="rotate(45, 32, 38)">
        <polygon
          points="32,16 29,38 32,40 35,38"
          fill="url(#revops-needle)"
        />
      </g>

      {/* Center hub */}
      <circle cx="32" cy="38" r="5" fill="#f8fafc" />
      <circle cx="32" cy="38" r="3" fill="#1e293b" />

      {/* RPM text */}
      <text
        x="32"
        y="52"
        textAnchor="middle"
        fill="#94a3b8"
        fontSize="6"
        fontFamily="system-ui, sans-serif"
        fontWeight="bold"
      >
        RPM
      </text>
    </svg>
  )
}
