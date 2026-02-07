interface PantherLogoProps {
  size?: number
  className?: string
}

export default function PantherLogo({ size = 32, className = '' }: PantherLogoProps) {
  return (
    <img
      src="/panther-logo.png"
      alt="Panther"
      width={size}
      height={size}
      className={`rounded-lg ${className}`}
    />
  )
}
