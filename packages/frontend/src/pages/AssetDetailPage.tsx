import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Route } from 'lucide-react'
import {
  useGetCloudAssetQuery,
  useGetCloudAssetFindingsQuery,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { formatRelativeTime } from '../lib/dateUtils'
import {
  AssetTypeBadge,
  ExposureBadge,
  SeverityBadge,
  SourceTypeBadge,
  StatusBadge,
} from '../components/cnapp/badges'
import { assetTypeLabel, riskScoreColor, severityRank } from '../lib/cnapp'

export default function AssetDetailPage() {
  const { assetId } = useParams<{ assetId: string }>()
  const [includeClosed, setIncludeClosed] = useState(false)

  const { data, isLoading, error } = useGetCloudAssetQuery(assetId!, {
    skip: !assetId,
  })
  const { data: findingsData, isLoading: findingsLoading } = useGetCloudAssetFindingsQuery(
    { assetId: assetId!, includeClosed },
    { skip: !assetId }
  )

  if (error) {
    return (
      <div className="p-4">
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
          Failed to load asset
        </div>
      </div>
    )
  }

  if (isLoading || !data) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  const { asset, relationships, attack_paths } = data

  const openAttackPaths = [...attack_paths]
    .filter((p) => p.status === 'open')
    .sort(
      (a, b) =>
        (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99) ||
        b.risk_score - a.risk_score
    )

  const findings = findingsData?.findings || []

  return (
    <div className="p-6">
      {/* Header */}
      <Link
        to="/assets"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors mb-4"
      >
        <ArrowLeft size={16} />
        Back to Assets
      </Link>

      <div className="flex flex-wrap items-center gap-3 mb-2">
        <h1 className="text-2xl font-bold text-foreground">{asset.name}</h1>
        <AssetTypeBadge assetType={asset.asset_type} />
        <ExposureBadge exposed={asset.internet_exposed} />
      </div>
      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm text-muted-foreground mb-6">
        <span>
          Provider: <span className="text-foreground">{asset.provider}</span>
        </span>
        {asset.region && (
          <span>
            Region: <span className="text-foreground">{asset.region}</span>
          </span>
        )}
        {asset.account_id && (
          <span>
            Account: <span className="text-foreground">{asset.account_id}</span>
          </span>
        )}
        <span>
          Criticality: <span className="text-foreground">{asset.criticality}</span>
        </span>
        {asset.data_classification && (
          <span>
            Data: <span className="text-foreground">{asset.data_classification}</span>
          </span>
        )}
        <span>
          First seen:{' '}
          <span className="text-foreground">{formatRelativeTime(asset.first_seen)}</span>
        </span>
        <span>
          Last seen:{' '}
          <span className="text-foreground">{formatRelativeTime(asset.last_seen)}</span>
        </span>
        {asset.sources.length > 0 && (
          <span>
            Sources: <span className="text-foreground">{asset.sources.join(', ')}</span>
          </span>
        )}
      </div>

      {/* Open attack paths */}
      <section className="mb-8">
        <h2 className="text-lg font-semibold text-foreground mb-3 flex items-center gap-2">
          <Route size={18} className="text-red-400" />
          Open Attack Paths ({openAttackPaths.length})
        </h2>
        {openAttackPaths.length === 0 ? (
          <div className="bg-card border border-border rounded-lg p-6 text-center text-muted-foreground">
            No open attack paths on this asset
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {openAttackPaths.map((path) => (
              <Link
                key={path.id}
                to={`/attack-paths/${path.id}`}
                className="bg-card border border-border rounded-lg p-4 hover:border-primary/50 transition-colors block"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={path.severity} />
                      <span className="px-2 py-0.5 text-xs rounded bg-muted text-muted-foreground font-mono truncate">
                        {path.rule_key}
                      </span>
                    </div>
                    <p className="font-medium text-foreground">{path.title}</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      First detected {formatRelativeTime(path.first_detected)}
                    </p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className={cn('text-2xl font-bold', riskScoreColor(path.risk_score))}>
                      {Math.round(path.risk_score)}
                    </p>
                    <p className="text-xs text-muted-foreground">risk</p>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </section>

      {/* Findings */}
      <section className="mb-8">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold text-foreground">
            Findings ({findings.length})
          </h2>
          <label className="flex items-center gap-2 text-sm text-foreground cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includeClosed}
              onChange={(e) => setIncludeClosed(e.target.checked)}
              className="rounded border-border"
            />
            Include closed
          </label>
        </div>
        {findingsLoading ? (
          <div className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
          </div>
        ) : (
          <div className="bg-card border border-border rounded-lg shadow-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-border">
                <thead className="bg-muted/50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Source
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Title
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Tags
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Detected
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {findings.map((finding) => (
                    <tr key={finding.id} className="hover:bg-muted/30 transition-colors">
                      <td className="px-6 py-4">
                        <SourceTypeBadge sourceType={finding.source_type} />
                      </td>
                      <td className="px-6 py-4">
                        <p className="text-sm text-foreground">{finding.title}</p>
                        {finding.rule_id && (
                          <p className="text-xs text-muted-foreground font-mono truncate max-w-xs">
                            {finding.rule_id}
                          </p>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="px-6 py-4">
                        <StatusBadge status={finding.status} />
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex flex-wrap gap-1 max-w-xs">
                          {(finding.tags || []).slice(0, 4).map((tag) => (
                            <span
                              key={tag}
                              className="px-2 py-0.5 text-xs rounded bg-muted text-muted-foreground"
                            >
                              {tag}
                            </span>
                          ))}
                          {(finding.tags || []).length > 4 && (
                            <span className="text-xs text-muted-foreground">
                              +{finding.tags.length - 4}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-muted-foreground whitespace-nowrap">
                        {finding.created_at_source
                          ? formatRelativeTime(finding.created_at_source)
                          : '-'}
                      </td>
                    </tr>
                  ))}
                  {findings.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-6 py-12 text-center text-muted-foreground">
                        No findings linked to this asset
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      {/* Relationships */}
      <section>
        <h2 className="text-lg font-semibold text-foreground mb-3">
          Relationships ({relationships.length})
        </h2>
        {relationships.length === 0 ? (
          <div className="bg-card border border-border rounded-lg p-6 text-center text-muted-foreground">
            No known relationships
          </div>
        ) : (
          <div className="bg-card border border-border rounded-lg divide-y divide-border">
            {relationships.map((rel) => (
              <div key={rel.id} className="flex items-center gap-3 px-4 py-3">
                <span className="px-2 py-0.5 text-xs rounded bg-muted text-muted-foreground font-mono">
                  {rel.relationship_type}
                </span>
                <ArrowRight
                  size={14}
                  className={cn(
                    'text-muted-foreground shrink-0',
                    rel.direction === 'inbound' && 'rotate-180'
                  )}
                />
                <Link
                  to={`/assets/${rel.related_asset.id}`}
                  className="text-primary hover:text-primary/80 font-medium text-sm"
                >
                  {rel.related_asset.name}
                </Link>
                <span className="text-xs text-muted-foreground">
                  {assetTypeLabel(rel.related_asset.asset_type)}
                </span>
                <span className="ml-auto text-xs text-muted-foreground capitalize">
                  {rel.direction}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
