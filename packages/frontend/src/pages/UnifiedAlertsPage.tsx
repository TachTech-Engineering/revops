import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertCircle,
  ExternalLink,
  Filter,
  RefreshCw,
  Search,
} from 'lucide-react'
import {
  useListUnifiedAlertsQuery,
  useListConnectorsQuery,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { formatDistanceToNow } from 'date-fns'

const severityConfig: Record<string, { color: string; label: string }> = {
  critical: { color: 'bg-red-500/20 text-red-400', label: 'Critical' },
  high: { color: 'bg-orange-500/20 text-orange-400', label: 'High' },
  medium: { color: 'bg-yellow-500/20 text-yellow-400', label: 'Medium' },
  low: { color: 'bg-blue-500/20 text-blue-400', label: 'Low' },
  info: { color: 'bg-gray-500/20 text-gray-400', label: 'Info' },
}

const statusConfig: Record<string, { color: string; label: string }> = {
  open: { color: 'bg-red-500/20 text-red-400', label: 'Open' },
  acknowledged: { color: 'bg-yellow-500/20 text-yellow-400', label: 'Acknowledged' },
  resolved: { color: 'bg-green-500/20 text-green-400', label: 'Resolved' },
  closed: { color: 'bg-gray-500/20 text-gray-400', label: 'Closed' },
}

const sourceTypeConfig: Record<string, { label: string; icon: string }> = {
  panther: { label: 'Panther', icon: '🐆' },
  google_secops: { label: 'Google SecOps', icon: '🔵' },
  splunk: { label: 'Splunk', icon: '🟢' },
  sentinel: { label: 'Sentinel', icon: '🔷' },
  elastic: { label: 'Elastic', icon: '🟡' },
}

export default function UnifiedAlertsPage() {
  const [filters, setFilters] = useState({
    source_type: '',
    severity: '',
    status: '',
    connector_id: '',
    page: 1,
    page_size: 25,
  })
  const [showFilters, setShowFilters] = useState(false)

  const { data: alerts, isLoading, refetch } = useListUnifiedAlertsQuery({
    source_type: filters.source_type || undefined,
    severity: filters.severity || undefined,
    status: filters.status || undefined,
    connector_id: filters.connector_id || undefined,
    page: filters.page,
    page_size: filters.page_size,
  })

  const { data: connectors } = useListConnectorsQuery({ category: 'data_source' })

  const handleFilterChange = (key: string, value: string) => {
    setFilters((prev) => ({ ...prev, [key]: value, page: 1 }))
  }

  const handlePageChange = (newPage: number) => {
    setFilters((prev) => ({ ...prev, page: newPage }))
  }

  const totalPages = Math.ceil((alerts?.total || 0) / filters.page_size)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Unified Alerts</h1>
          <p className="text-muted-foreground">
            All alerts from connected data sources in one view
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-md font-medium',
              showFilters ? 'bg-accent' : 'bg-muted hover:bg-accent'
            )}
          >
            <Filter size={18} />
            Filters
          </button>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-4 py-2 bg-muted text-muted-foreground rounded-md font-medium hover:bg-accent"
          >
            <RefreshCw size={18} className={isLoading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters Panel */}
      {showFilters && (
        <div className="rounded-lg border bg-background p-4">
          <div className="grid grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">Source</label>
              <select
                value={filters.source_type}
                onChange={(e) => handleFilterChange('source_type', e.target.value)}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm"
              >
                <option value="">All Sources</option>
                {Object.entries(sourceTypeConfig).map(([key, cfg]) => (
                  <option key={key} value={key}>
                    {cfg.icon} {cfg.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Connector</label>
              <select
                value={filters.connector_id}
                onChange={(e) => handleFilterChange('connector_id', e.target.value)}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm"
              >
                <option value="">All Connectors</option>
                {connectors?.items.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Severity</label>
              <select
                value={filters.severity}
                onChange={(e) => handleFilterChange('severity', e.target.value)}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm"
              >
                <option value="">All Severities</option>
                {Object.entries(severityConfig).map(([key, cfg]) => (
                  <option key={key} value={key}>
                    {cfg.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Status</label>
              <select
                value={filters.status}
                onChange={(e) => handleFilterChange('status', e.target.value)}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm"
              >
                <option value="">All Statuses</option>
                {Object.entries(statusConfig).map(([key, cfg]) => (
                  <option key={key} value={key}>
                    {cfg.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Stats */}
      {alerts && (
        <div className="grid grid-cols-5 gap-4">
          <div className="rounded-lg border bg-background p-4">
            <div className="text-2xl font-bold">{alerts.total}</div>
            <div className="text-sm text-muted-foreground">Total Alerts</div>
          </div>
          {Object.entries(severityConfig).map(([key, cfg]) => {
            const count = alerts.items.filter((a) => a.severity === key).length
            return (
              <div key={key} className="rounded-lg border bg-background p-4">
                <div className={cn('text-2xl font-bold', cfg.color.split(' ')[1])}>
                  {count}
                </div>
                <div className="text-sm text-muted-foreground">{cfg.label}</div>
              </div>
            )
          })}
        </div>
      )}

      {/* Alerts Table */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading alerts...</div>
        ) : alerts?.items.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground">
            <Search size={48} className="mx-auto mb-4 opacity-20" />
            <p>No alerts found</p>
            <p className="text-sm mt-2">
              Configure data source connectors to start ingesting alerts
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="text-left p-3 font-medium">Source</th>
                    <th className="text-left p-3 font-medium">Title</th>
                    <th className="text-left p-3 font-medium">Severity</th>
                    <th className="text-left p-3 font-medium">Status</th>
                    <th className="text-left p-3 font-medium">Rule</th>
                    <th className="text-left p-3 font-medium">Time</th>
                    <th className="text-left p-3 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {alerts?.items.map((alert) => {
                    const sourceInfo = sourceTypeConfig[alert.source_type] || {
                      label: alert.source_type,
                      icon: '📦',
                    }
                    const severityInfo = severityConfig[alert.severity] || {
                      color: 'bg-gray-500/20 text-gray-400',
                      label: alert.severity,
                    }
                    const statusInfo = statusConfig[alert.status] || {
                      color: 'bg-gray-500/20 text-gray-400',
                      label: alert.status,
                    }

                    return (
                      <tr key={alert.id} className="hover:bg-muted/50">
                        <td className="p-3">
                          <div className="flex items-center gap-2">
                            <span className="text-lg">{sourceInfo.icon}</span>
                            <span className="text-sm">{sourceInfo.label}</span>
                          </div>
                        </td>
                        <td className="p-3">
                          <div className="font-medium max-w-md truncate">{alert.title}</div>
                          {alert.description && (
                            <div className="text-xs text-muted-foreground truncate max-w-md">
                              {alert.description}
                            </div>
                          )}
                        </td>
                        <td className="p-3">
                          <span
                            className={cn(
                              'px-2 py-0.5 rounded text-xs font-medium',
                              severityInfo.color
                            )}
                          >
                            {severityInfo.label}
                          </span>
                        </td>
                        <td className="p-3">
                          <span
                            className={cn(
                              'px-2 py-0.5 rounded text-xs font-medium',
                              statusInfo.color
                            )}
                          >
                            {statusInfo.label}
                          </span>
                        </td>
                        <td className="p-3 text-sm text-muted-foreground">
                          {alert.rule_name || '-'}
                        </td>
                        <td className="p-3 text-sm text-muted-foreground">
                          {formatDistanceToNow(new Date(alert.created_at_source), {
                            addSuffix: true,
                          })}
                        </td>
                        <td className="p-3">
                          <div className="flex items-center gap-2">
                            <Link
                              to={`/alerts/${alert.id}`}
                              className="p-1 hover:bg-accent rounded"
                              title="View Details"
                            >
                              <AlertCircle size={16} />
                            </Link>
                            {alert.raw_data && (
                              <button
                                onClick={() => {
                                  // Show raw data in modal or console
                                  console.log('Raw data:', alert.raw_data)
                                }}
                                className="p-1 hover:bg-accent rounded"
                                title="View Raw Data"
                              >
                                <ExternalLink size={16} />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between p-4 border-t">
                <div className="text-sm text-muted-foreground">
                  Showing {(filters.page - 1) * filters.page_size + 1} to{' '}
                  {Math.min(filters.page * filters.page_size, alerts.total)} of {alerts.total}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handlePageChange(filters.page - 1)}
                    disabled={filters.page === 1}
                    className="px-3 py-1 rounded-md bg-muted hover:bg-accent disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <span className="text-sm">
                    Page {filters.page} of {totalPages}
                  </span>
                  <button
                    onClick={() => handlePageChange(filters.page + 1)}
                    disabled={filters.page >= totalPages}
                    className="px-3 py-1 rounded-md bg-muted hover:bg-accent disabled:opacity-50"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
