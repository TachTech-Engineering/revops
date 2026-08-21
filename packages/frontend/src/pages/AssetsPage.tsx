import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Boxes, Globe, Search, UserCog } from 'lucide-react'
import {
  useListCloudAssetsQuery,
  useGetCloudAssetSummaryQuery,
  useGetCiemSummaryQuery,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { formatRelativeTime } from '../lib/dateUtils'
import { AssetTypeBadge, ExposureBadge, SeverityBadge } from '../components/cnapp/badges'
import { assetTypeLabels, riskScoreColor, severityRank } from '../lib/cnapp'

const RISKY_IDENTITY_LIMIT = 10

const PAGE_SIZE = 25

export default function AssetsPage() {
  const navigate = useNavigate()
  const [typeFilter, setTypeFilter] = useState('')
  const [providerFilter, setProviderFilter] = useState('')
  const [exposedOnly, setExposedOnly] = useState(false)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)

  const { data: summary } = useGetCloudAssetSummaryQuery()
  const { data: ciem } = useGetCiemSummaryQuery()

  const { data, isLoading, error } = useListCloudAssetsQuery({
    assetType: typeFilter || undefined,
    provider: providerFilter || undefined,
    exposedOnly,
    search: search || undefined,
    limit: PAGE_SIZE,
    offset: (page - 1) * PAGE_SIZE,
  })

  const resetPage = () => setPage(1)

  const providers = Object.keys(summary?.by_provider || {}).sort()

  // Identity Risk (CIEM) rollup — hidden entirely when there is nothing to show.
  const showIdentityRisk =
    !!ciem && (ciem.identity_assets > 0 || ciem.risky_identities.length > 0)
  const identityFindingSeverities = Object.entries(
    ciem?.open_identity_findings_by_severity || {}
  )
    .filter(([, count]) => count > 0)
    .sort(([a], [b]) => (severityRank[a] ?? 99) - (severityRank[b] ?? 99))
  const riskyIdentities = (ciem?.risky_identities || []).slice(0, RISKY_IDENTITY_LIMIT)

  if (error) {
    return (
      <div className="p-4">
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
          Failed to load assets
        </div>
      </div>
    )
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Assets</h1>
          <p className="text-muted-foreground mt-1">
            Cloud asset inventory across providers and clusters
          </p>
        </div>
      </div>

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <Boxes size={16} />
              Total Assets
            </div>
            <p className="text-2xl font-bold text-foreground mt-1">{summary.total}</p>
          </div>
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <Globe size={16} />
              Internet Exposed
            </div>
            <p
              className={cn(
                'text-2xl font-bold mt-1',
                summary.internet_exposed > 0 ? 'text-red-400' : 'text-foreground'
              )}
            >
              {summary.internet_exposed}
            </p>
          </div>
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="text-muted-foreground text-sm">By Provider</div>
            <div className="flex flex-wrap gap-2 mt-2">
              {providers.length === 0 && (
                <span className="text-sm text-muted-foreground">No providers</span>
              )}
              {providers.map((provider) => (
                <button
                  key={provider}
                  onClick={() => {
                    setProviderFilter(providerFilter === provider ? '' : provider)
                    resetPage()
                  }}
                  className={cn(
                    'px-2 py-1 text-xs font-medium rounded-full transition-colors',
                    providerFilter === provider
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-muted text-muted-foreground hover:text-foreground'
                  )}
                >
                  {provider} ({summary.by_provider[provider]})
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Identity Risk (CIEM) */}
      {showIdentityRisk && ciem && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold text-foreground mb-3">Identity Risk</h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-card border border-border rounded-lg p-4">
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <UserCog size={16} />
                Identity Assets
              </div>
              <p className="text-2xl font-bold text-foreground mt-1">
                {ciem.identity_assets}
              </p>
            </div>
            <div className="bg-card border border-border rounded-lg p-4 sm:col-span-2">
              <div className="text-muted-foreground text-sm">
                Open Identity Findings
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 mt-2">
                {identityFindingSeverities.length === 0 && (
                  <span className="text-sm text-muted-foreground">No open findings</span>
                )}
                {identityFindingSeverities.map(([severity, count]) => (
                  <div key={severity} className="flex items-center gap-1.5">
                    <SeverityBadge severity={severity} />
                    <span className="text-sm font-medium text-foreground">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {riskyIdentities.length > 0 && (
            <div className="mt-4 bg-card border border-border rounded-lg shadow-sm overflow-hidden">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-border">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        Risky Identity
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        Type
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        Provider
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        Severity
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        Risk Score
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {riskyIdentities.map((identity) => (
                      <tr
                        key={identity.finding_id}
                        onClick={() => navigate(`/attack-paths/${identity.finding_id}`)}
                        className="hover:bg-muted/30 transition-colors cursor-pointer"
                      >
                        <td className="px-6 py-4">
                          <span className="text-primary font-medium">{identity.name}</span>
                          <p className="text-xs text-muted-foreground truncate max-w-xs">
                            {identity.title}
                          </p>
                        </td>
                        <td className="px-6 py-4">
                          <AssetTypeBadge assetType={identity.asset_type} />
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-sm text-foreground">{identity.provider}</span>
                          {identity.account_id && (
                            <p className="text-xs text-muted-foreground truncate max-w-xs">
                              {identity.account_id}
                            </p>
                          )}
                        </td>
                        <td className="px-6 py-4">
                          <SeverityBadge severity={identity.severity} />
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={cn(
                              'text-sm font-bold',
                              riskScoreColor(identity.risk_score)
                            )}
                          >
                            {Math.round(identity.risk_score)}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-4 mb-6 items-center">
        <div className="relative">
          <Search
            size={16}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
          />
          <input
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              resetPage()
            }}
            placeholder="Search assets..."
            className="pl-9 pr-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary w-64"
          />
        </div>

        <select
          value={typeFilter}
          onChange={(e) => {
            setTypeFilter(e.target.value)
            resetPage()
          }}
          className="px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
        >
          <option value="">All Types</option>
          {Object.entries(assetTypeLabels).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>

        <select
          value={providerFilter}
          onChange={(e) => {
            setProviderFilter(e.target.value)
            resetPage()
          }}
          className="px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
        >
          <option value="">All Providers</option>
          {providers.map((provider) => (
            <option key={provider} value={provider}>
              {provider}
            </option>
          ))}
        </select>

        <label className="flex items-center gap-2 text-sm text-foreground cursor-pointer select-none">
          <input
            type="checkbox"
            checked={exposedOnly}
            onChange={(e) => {
              setExposedOnly(e.target.checked)
              resetPage()
            }}
            className="rounded border-border"
          />
          Internet exposed only
        </label>
      </div>

      {/* Assets table */}
      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : (
        <>
          <div className="bg-card border border-border rounded-lg shadow-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-border">
                <thead className="bg-muted/50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Provider
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Region
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Exposure
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Criticality
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Open Findings
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Attack Paths
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Last Seen
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {data?.assets.map((asset) => (
                    <tr
                      key={asset.id}
                      onClick={() => navigate(`/assets/${asset.id}`)}
                      className="hover:bg-muted/30 transition-colors cursor-pointer"
                    >
                      <td className="px-6 py-4">
                        <span className="text-primary font-medium">{asset.name}</span>
                        {asset.account_id && (
                          <p className="text-xs text-muted-foreground truncate max-w-xs">
                            {asset.account_id}
                          </p>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <AssetTypeBadge assetType={asset.asset_type} />
                      </td>
                      <td className="px-6 py-4 text-sm text-foreground">{asset.provider}</td>
                      <td className="px-6 py-4 text-sm text-muted-foreground">
                        {asset.region || '-'}
                      </td>
                      <td className="px-6 py-4">
                        <ExposureBadge exposed={asset.internet_exposed} />
                      </td>
                      <td className="px-6 py-4 text-sm text-foreground">{asset.criticality}</td>
                      <td className="px-6 py-4 text-sm text-foreground">
                        {asset.open_alert_count}
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={cn(
                            'text-sm font-medium',
                            asset.open_attack_path_count > 0
                              ? 'text-red-400'
                              : 'text-muted-foreground'
                          )}
                        >
                          {asset.open_attack_path_count}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-muted-foreground whitespace-nowrap">
                        {formatRelativeTime(asset.last_seen)}
                      </td>
                    </tr>
                  ))}
                  {data?.assets.length === 0 && (
                    <tr>
                      <td colSpan={9} className="px-6 py-12 text-center text-muted-foreground">
                        No assets found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination */}
          {data && data.total > PAGE_SIZE && (
            <div className="mt-4 flex justify-between items-center">
              <p className="text-sm text-muted-foreground">
                Showing {(page - 1) * PAGE_SIZE + 1} to {Math.min(page * PAGE_SIZE, data.total)} of{' '}
                {data.total} assets
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
