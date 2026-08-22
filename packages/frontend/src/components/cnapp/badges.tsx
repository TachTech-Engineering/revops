/**
 * Shared badge components for the CNAPP pages
 * (Assets, Asset detail, Attack Paths, Attack Path detail).
 *
 * Styling mirrors the severity/status chip conventions used by
 * UnifiedAlertsPage / IncidentsPage so the new pages match the
 * rest of the app in both themes. Non-component helpers live in
 * src/lib/cnapp.ts.
 */
import { cn } from '../../lib/utils'
import { severityConfig, assetTypeLabel } from '../../lib/cnapp'

export function SeverityBadge({ severity }: { severity: string }) {
  const cfg = severityConfig[severity?.toLowerCase()] || {
    color: 'bg-gray-500/20 text-gray-400',
    label: severity || 'Unknown',
  }
  return (
    <span className={cn('px-2 py-1 text-xs font-medium rounded-full whitespace-nowrap', cfg.color)}>
      {cfg.label}
    </span>
  )
}

const findingStatusConfig: Record<string, string> = {
  open: 'bg-red-500/20 text-red-400',
  acknowledged: 'bg-yellow-500/20 text-yellow-400',
  resolved: 'bg-green-500/20 text-green-400',
  dismissed: 'bg-gray-500/20 text-gray-400',
  closed: 'bg-gray-500/20 text-gray-400',
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={cn(
        'px-2 py-1 text-xs font-medium rounded-full capitalize whitespace-nowrap',
        findingStatusConfig[status?.toLowerCase()] || 'bg-muted text-muted-foreground'
      )}
    >
      {status}
    </span>
  )
}

// Alert source scanners feeding CNAPP findings, plus the raw log sources
// RevOps ingests directly (Raw Logs page).
const sourceTypeConfig: Record<string, { color: string; label: string }> = {
  falco: { color: 'bg-teal-500/20 text-teal-400', label: 'Falco' },
  prowler: { color: 'bg-purple-500/20 text-purple-400', label: 'Prowler' },
  trivy: { color: 'bg-sky-500/20 text-sky-400', label: 'Trivy' },
  unifi_syslog: { color: 'bg-indigo-500/20 text-indigo-400', label: 'UniFi Syslog' },
}

export function SourceTypeBadge({ sourceType }: { sourceType: string }) {
  const cfg = sourceTypeConfig[sourceType?.toLowerCase()] || {
    color: 'bg-muted text-muted-foreground',
    label: sourceType || 'unknown',
  }
  return (
    <span className={cn('px-2 py-1 text-xs font-medium rounded-full whitespace-nowrap', cfg.color)}>
      {cfg.label}
    </span>
  )
}

export function AssetTypeBadge({ assetType }: { assetType: string }) {
  return (
    <span className="px-2 py-1 text-xs font-medium rounded-full bg-muted text-muted-foreground whitespace-nowrap">
      {assetTypeLabel(assetType)}
    </span>
  )
}

export function ExposureBadge({ exposed }: { exposed: boolean }) {
  if (!exposed) {
    return <span className="text-sm text-muted-foreground">Internal</span>
  }
  return (
    <span className="px-2 py-1 text-xs font-medium rounded-full bg-red-500/20 text-red-400 whitespace-nowrap">
      Internet Exposed
    </span>
  )
}
