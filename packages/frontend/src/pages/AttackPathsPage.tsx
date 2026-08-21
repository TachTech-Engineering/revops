import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'
import {
  useListAttackPathsQuery,
  useGetAttackPathSummaryQuery,
  type AttackPathStatusFilter,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { formatRelativeTime } from '../lib/dateUtils'
import { SeverityBadge, StatusBadge } from '../components/cnapp/badges'
import { assetTypeLabel, riskScoreColor, severityConfig } from '../lib/cnapp'

const PAGE_SIZE = 25

const statusTabs: { value: AttackPathStatusFilter; label: string }[] = [
  { value: 'open', label: 'Open' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'dismissed', label: 'Dismissed' },
  { value: 'all', label: 'All' },
]

const summarySeverities = ['critical', 'high', 'medium', 'low'] as const

export default function AttackPathsPage() {
  const navigate = useNavigate()
  const [status, setStatus] = useState<AttackPathStatusFilter>('open')
  const [severityFilter, setSeverityFilter] = useState('')
  const [page, setPage] = useState(1)

  const { data: summary } = useGetAttackPathSummaryQuery()

  const { data, isLoading, error } = useListAttackPathsQuery({
    status,
    severity: severityFilter || undefined,
    limit: PAGE_SIZE,
    offset: (page - 1) * PAGE_SIZE,
  })

  if (error) {
    return (
      <div className="p-4">
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
          Failed to load attack paths
        </div>
      </div>
    )
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Attack Paths</h1>
          <p className="text-muted-foreground mt-1">
            Toxic combinations of exposure, vulnerability, and blast radius
          </p>
        </div>
      </div>

      {/* Open-by-severity summary cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          {summarySeverities.map((sev) => {
            const count = summary.open_by_severity[sev] || 0
            const cfg = severityConfig[sev]
            return (
              <button
                key={sev}
                onClick={() => {
                  setSeverityFilter(severityFilter === sev ? '' : sev)
                  setStatus('open')
                  setPage(1)
                }}
                className={cn(
                  'bg-card border rounded-lg p-4 text-left transition-colors',
                  severityFilter === sev
                    ? 'border-primary'
                    : 'border-border hover:border-primary/50'
                )}
              >
                <div className="flex items-center justify-between">
                  <span
                    className={cn('px-2 py-1 text-xs font-medium rounded-full', cfg.color)}
                  >
                    {cfg.label}
                  </span>
                  {sev === 'critical' && count > 0 && (
                    <AlertTriangle size={16} className="text-red-400" />
                  )}
                </div>
                <p className="text-2xl font-bold text-foreground mt-2">{count}</p>
                <p className="text-xs text-muted-foreground">open</p>
              </button>
            )
          })}
        </div>
      )}

      {/* Status tabs */}
      <div className="flex items-center gap-1 border-b border-border mb-6">
        {statusTabs.map((tab) => (
          <button
            key={tab.value}
            onClick={() => {
              setStatus(tab.value)
              setPage(1)
            }}
            className={cn(
              'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
              status === tab.value
                ? 'border-primary text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            )}
          >
            {tab.label}
            {tab.value !== 'all' && summary?.by_status?.[tab.value] !== undefined && (
              <span className="ml-1.5 text-xs text-muted-foreground">
                {summary.by_status[tab.value]}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Findings list */}
      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : (
        <>
          <div className="bg-card border border-border rounded-lg shadow-sm divide-y divide-border">
            {data?.findings.map((finding) => (
              <div
                key={finding.id}
                onClick={() => navigate(`/attack-paths/${finding.id}`)}
                className="flex items-center gap-4 px-4 py-4 hover:bg-muted/30 transition-colors cursor-pointer"
              >
                {/* Risk score */}
                <div className="w-14 text-center shrink-0">
                  <p className={cn('text-2xl font-bold', riskScoreColor(finding.risk_score))}>
                    {Math.round(finding.risk_score)}
                  </p>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    risk
                  </p>
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <SeverityBadge severity={finding.severity} />
                    {finding.status !== 'open' && <StatusBadge status={finding.status} />}
                    <span className="font-medium text-foreground truncate">
                      {finding.title}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                    <span className="text-foreground">
                      {finding.asset.name}
                      <span className="text-muted-foreground">
                        {' '}
                        · {assetTypeLabel(finding.asset.asset_type)}
                      </span>
                    </span>
                    <span className="px-2 py-0.5 rounded bg-muted font-mono">
                      {finding.rule_key}
                    </span>
                    <span>
                      {finding.evidence_count} evidence alert
                      {finding.evidence_count === 1 ? '' : 's'}
                    </span>
                    <span>first detected {formatRelativeTime(finding.first_detected)}</span>
                    {finding.incident_id && (
                      <Link
                        to={`/incidents/${finding.incident_id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-primary hover:text-primary/80"
                      >
                        View incident
                      </Link>
                    )}
                  </div>
                </div>
              </div>
            ))}
            {data?.findings.length === 0 && (
              <div className="px-6 py-12 text-center text-muted-foreground">
                No attack path findings
              </div>
            )}
          </div>

          {/* Pagination */}
          {data && data.total > PAGE_SIZE && (
            <div className="mt-4 flex justify-between items-center">
              <p className="text-sm text-muted-foreground">
                Showing {(page - 1) * PAGE_SIZE + 1} to {Math.min(page * PAGE_SIZE, data.total)}{' '}
                of {data.total} findings
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 border border-border rounded text-sm text-foreground hover:bg-muted disabled:opacity-50 transition-colors"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  disabled={page * PAGE_SIZE >= data.total}
                  className="px-3 py-1 border border-border rounded text-sm text-foreground hover:bg-muted disabled:opacity-50 transition-colors"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
