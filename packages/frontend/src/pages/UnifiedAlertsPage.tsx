import { useState, ReactNode, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertCircle,
  ExternalLink,
  Filter,
  RefreshCw,
  Search,
  CheckSquare,
  Square,
  XCircle,
  CheckCircle2,
  UserPlus,
  Archive,
  Trash2,
} from 'lucide-react'
import {
  useListUnifiedAlertsQuery,
  useListConnectorsQuery,
  useBulkUpdateAlertsMutation,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { formatRelativeTime } from '../lib/dateUtils'
import PantherLogo from '../components/common/PantherLogo'

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

const sourceTypeConfig: Record<string, { label: string; icon: string | ReactNode; category: string }> = {
  // SIEM
  panther: { label: 'Panther', icon: <PantherLogo size={20} />, category: 'SIEM' },
  google_secops: { label: 'Google SecOps', icon: '🔵', category: 'SIEM' },
  splunk: { label: 'Splunk', icon: '🟢', category: 'SIEM' },
  sentinel: { label: 'Sentinel', icon: '🔷', category: 'SIEM' },
  elastic: { label: 'Elastic', icon: '🟡', category: 'SIEM' },
  sumo_logic: { label: 'Sumo Logic', icon: '🟣', category: 'SIEM' },
  // EDR
  crowdstrike_falcon: { label: 'CrowdStrike Falcon', icon: <img src="/icons/crowdstrike.png" alt="CrowdStrike" className="w-5 h-5 object-contain" />, category: 'EDR' },
  sentinelone: { label: 'SentinelOne', icon: '🟣', category: 'EDR' },
  microsoft_defender: { label: 'Microsoft Defender', icon: '🛡️', category: 'EDR' },
  carbon_black: { label: 'Carbon Black', icon: '⬛', category: 'EDR' },
  // XDR
  cortex_xdr: { label: 'Cortex XDR', icon: '🔶', category: 'XDR' },
  trend_vision_one: { label: 'Trend Vision One', icon: '🔺', category: 'XDR' },
  // Cloud Security
  aws_security_hub: { label: 'AWS Security Hub', icon: '🟠', category: 'Cloud' },
  aws_guardduty: { label: 'AWS GuardDuty', icon: '🟠', category: 'Cloud' },
  gcp_scc: { label: 'GCP Security Command Center', icon: '🔵', category: 'Cloud' },
  azure_defender: { label: 'Azure Defender', icon: '🔷', category: 'Cloud' },
  wiz: { label: 'Wiz', icon: '💎', category: 'Cloud' },
  orca: { label: 'Orca', icon: '🐋', category: 'Cloud' },
  // Identity
  okta: { label: 'Okta', icon: '🔐', category: 'Identity' },
  entra_id: { label: 'Microsoft Entra ID', icon: '🔷', category: 'Identity' },
  azure_ad_identity: { label: 'Azure AD Identity', icon: '🔷', category: 'Identity' },
  crowdstrike_identity: { label: 'CrowdStrike Identity', icon: '🔴', category: 'Identity' },
  // Email Security
  proofpoint: { label: 'Proofpoint', icon: '📧', category: 'Email' },
  mimecast: { label: 'Mimecast', icon: '📨', category: 'Email' },
  microsoft_defender_email: { label: 'Defender for Office 365', icon: '📬', category: 'Email' },
  // Network Security
  cloudflare: { label: 'Cloudflare', icon: '🟠', category: 'Network' },
  darktrace: { label: 'Darktrace', icon: '🌐', category: 'Network' },
  vectra: { label: 'Vectra', icon: '📡', category: 'Network' },
}

type AlertTab = 'active' | 'resolved'

export default function UnifiedAlertsPage() {
  const [activeTab, setActiveTab] = useState<AlertTab>('active')
  const [filters, setFilters] = useState({
    source_type: '',
    severity: '',
    status: '',
    connector_id: '',
    start_date: '',
    end_date: '',
    page: 1,
    page_size: 25,
  })
  const [showFilters, setShowFilters] = useState(false)
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())
  const [bulkUpdateAlerts] = useBulkUpdateAlertsMutation()

  // Determine status filter based on tab
  const getStatusFilter = () => {
    if (filters.status) return filters.status // User manually selected a status
    if (activeTab === 'resolved') return 'resolved'
    return undefined // Active tab shows all non-resolved (handled by exclude_resolved param)
  }

  const { data: alerts, isLoading, refetch } = useListUnifiedAlertsQuery({
    source_type: filters.source_type || undefined,
    severity: filters.severity || undefined,
    status: getStatusFilter(),
    connector_id: filters.connector_id || undefined,
    start_date: filters.start_date || undefined,
    end_date: filters.end_date || undefined,
    page: filters.page,
    page_size: filters.page_size,
    exclude_resolved: activeTab === 'active' && !filters.status ? true : undefined,
  })

  const { data: connectors } = useListConnectorsQuery({ category: 'data_source' })

  // Selection helpers
  const allVisibleIds = useMemo(() =>
    alerts?.items.map(a => a.id) || [],
    [alerts?.items]
  )

  const isAllSelected = allVisibleIds.length > 0 &&
    allVisibleIds.every(id => selectedAlerts.has(id))

  const isSomeSelected = selectedAlerts.size > 0

  const toggleSelectAll = () => {
    if (isAllSelected) {
      setSelectedAlerts(new Set())
    } else {
      setSelectedAlerts(new Set(allVisibleIds))
    }
  }

  const toggleSelectOne = (id: string) => {
    const newSelected = new Set(selectedAlerts)
    if (newSelected.has(id)) {
      newSelected.delete(id)
    } else {
      newSelected.add(id)
    }
    setSelectedAlerts(newSelected)
  }

  const clearSelection = () => {
    setSelectedAlerts(new Set())
  }

  const handleBulkAction = async (action: string, value?: string) => {
    if (selectedAlerts.size === 0) return

    try {
      await bulkUpdateAlerts({
        alert_ids: Array.from(selectedAlerts),
        action,
        value,
      }).unwrap()

      clearSelection()
      refetch()
    } catch (error) {
      console.error('Bulk action failed:', error)
    }
  }

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
          <h1 className="text-3xl font-bold">Alerts</h1>
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

      {/* Tabs for Active vs Resolved */}
      <div className="flex items-center gap-1 border-b">
        <button
          onClick={() => {
            setActiveTab('active')
            setFilters((prev) => ({ ...prev, status: '', page: 1 }))
          }}
          className={cn(
            'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
            activeTab === 'active'
              ? 'border-primary text-foreground'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          Active Alerts
        </button>
        <button
          onClick={() => {
            setActiveTab('resolved')
            setFilters((prev) => ({ ...prev, status: '', page: 1 }))
          }}
          className={cn(
            'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
            activeTab === 'resolved'
              ? 'border-primary text-foreground'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          Resolved
        </button>
      </div>

      {/* Filters Panel */}
      {showFilters && (
        <div className="rounded-lg border bg-background p-4 space-y-4">
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
          <div className="grid grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">Start Date</label>
              <input
                type="date"
                value={filters.start_date}
                onChange={(e) => handleFilterChange('start_date', e.target.value)}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">End Date</label>
              <input
                type="date"
                value={filters.end_date}
                onChange={(e) => handleFilterChange('end_date', e.target.value)}
                className="w-full px-3 py-2 rounded-md border bg-background text-sm"
              />
            </div>
            <div className="col-span-2 flex items-end">
              <button
                onClick={() => setFilters((prev) => ({ ...prev, start_date: '', end_date: '', page: 1 }))}
                className="px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
              >
                Clear dates
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Actions Toolbar */}
      {isSomeSelected && (
        <div className="rounded-lg border bg-primary/10 p-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className="font-medium text-primary">
              {selectedAlerts.size} alert{selectedAlerts.size !== 1 ? 's' : ''} selected
            </span>
            <button
              onClick={clearSelection}
              className="text-sm text-muted-foreground hover:text-foreground flex items-center gap-1"
            >
              <XCircle size={14} />
              Clear
            </button>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleBulkAction('acknowledge')}
              className="flex items-center gap-2 px-3 py-1.5 bg-yellow-500/20 text-yellow-400 rounded-md text-sm font-medium hover:bg-yellow-500/30"
            >
              <CheckCircle2 size={16} />
              Acknowledge
            </button>
            <button
              onClick={() => handleBulkAction('resolve')}
              className="flex items-center gap-2 px-3 py-1.5 bg-green-500/20 text-green-400 rounded-md text-sm font-medium hover:bg-green-500/30"
            >
              <CheckSquare size={16} />
              Resolve
            </button>
            <button
              onClick={() => handleBulkAction('close')}
              className="flex items-center gap-2 px-3 py-1.5 bg-gray-500/20 text-gray-400 rounded-md text-sm font-medium hover:bg-gray-500/30"
            >
              <Archive size={16} />
              Close
            </button>
            <div className="w-px h-6 bg-border mx-1" />
            <select
              onChange={(e) => {
                if (e.target.value) {
                  handleBulkAction('set_severity', e.target.value)
                  e.target.value = ''
                }
              }}
              className="px-3 py-1.5 bg-muted rounded-md text-sm font-medium border-0"
              defaultValue=""
            >
              <option value="" disabled>Set Severity...</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>
      )}

      {/* Stats - Clickable severity filters */}
      {alerts && (
        <div className="grid grid-cols-6 gap-4">
          <button
            onClick={() => handleFilterChange('severity', '')}
            className={cn(
              'rounded-lg border bg-background p-4 text-left transition-all hover:border-primary/50',
              !filters.severity && 'ring-2 ring-primary border-primary'
            )}
          >
            <div className="text-2xl font-bold">
              {Object.values(alerts.severity_counts || {}).reduce((a, b) => a + b, 0)}
            </div>
            <div className="text-sm text-muted-foreground">Total Alerts</div>
          </button>
          {Object.entries(severityConfig).map(([key, cfg]) => {
            const count = alerts.severity_counts?.[key] || 0
            const isActive = filters.severity === key
            return (
              <button
                key={key}
                onClick={() => handleFilterChange('severity', isActive ? '' : key)}
                className={cn(
                  'rounded-lg border bg-background p-4 text-left transition-all hover:border-primary/50',
                  isActive && 'ring-2 ring-primary border-primary'
                )}
              >
                <div className={cn('text-2xl font-bold', cfg.color.split(' ')[1])}>
                  {count}
                </div>
                <div className="text-sm text-muted-foreground">{cfg.label}</div>
              </button>
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
                    <th className="text-left p-3 font-medium w-10">
                      <button
                        onClick={toggleSelectAll}
                        className="flex items-center justify-center hover:text-primary"
                      >
                        {isAllSelected ? (
                          <CheckSquare size={18} className="text-primary" />
                        ) : (
                          <Square size={18} />
                        )}
                      </button>
                    </th>
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
                      <tr
                        key={alert.id}
                        className={cn(
                          'hover:bg-muted/50',
                          selectedAlerts.has(alert.id) && 'bg-primary/5'
                        )}
                      >
                        <td className="p-3">
                          <button
                            onClick={() => toggleSelectOne(alert.id)}
                            className="flex items-center justify-center hover:text-primary"
                          >
                            {selectedAlerts.has(alert.id) ? (
                              <CheckSquare size={18} className="text-primary" />
                            ) : (
                              <Square size={18} />
                            )}
                          </button>
                        </td>
                        <td className="p-3">
                          <div className="flex items-center gap-2">
                            {typeof sourceInfo.icon === 'string' ? (
                              <span className="text-lg">{sourceInfo.icon}</span>
                            ) : (
                              <span className="flex items-center">{sourceInfo.icon}</span>
                            )}
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
                          {formatRelativeTime(alert.created_at_source)}
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
                  {Math.min(filters.page * filters.page_size, alerts?.total ?? 0)} of {alerts?.total ?? 0}
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
