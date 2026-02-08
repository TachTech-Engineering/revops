import { useState, ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  Plus,
  Trash2,
  Edit2,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  Database,
  Zap,
  Play,
  Settings,
  RotateCcw,
} from 'lucide-react'
import {
  useListConnectorsQuery,
  useDeleteConnectorMutation,
  useTestConnectorMutation,
  useSyncConnectorMutation,
  ConnectorCategory,
  ConnectorStatus,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { formatDistanceToNow } from 'date-fns'
import PantherLogo from '../components/common/PantherLogo'

const statusConfig: Record<ConnectorStatus, { label: string; color: string; icon: typeof CheckCircle }> = {
  connected: { label: 'Connected', color: 'bg-green-500/20 text-green-400', icon: CheckCircle },
  error: { label: 'Error', color: 'bg-red-500/20 text-red-400', icon: XCircle },
  disabled: { label: 'Disabled', color: 'bg-gray-500/20 text-gray-400', icon: Clock },
  pending: { label: 'Pending', color: 'bg-yellow-500/20 text-yellow-400', icon: Clock },
}

const connectorTypeLabels: Record<string, { label: string; icon: string | ReactNode; category?: string }> = {
  // SIEM
  panther: { label: 'Panther', icon: <PantherLogo size={28} />, category: 'SIEM' },
  google_secops: { label: 'Google SecOps', icon: '🔵', category: 'SIEM' },
  splunk: { label: 'Splunk', icon: '🟢', category: 'SIEM' },
  sentinel: { label: 'Microsoft Sentinel', icon: '🔷', category: 'SIEM' },
  elastic: { label: 'Elastic Security', icon: '🟡', category: 'SIEM' },
  sumo_logic: { label: 'Sumo Logic', icon: '🟣', category: 'SIEM' },
  // EDR
  crowdstrike_falcon: { label: 'CrowdStrike Falcon', icon: <img src="/icons/crowdstrike.png" alt="CrowdStrike" className="w-7 h-7 object-contain" />, category: 'EDR' },
  sentinelone: { label: 'SentinelOne', icon: '🟣', category: 'EDR' },
  microsoft_defender: { label: 'Microsoft Defender', icon: '🛡️', category: 'EDR' },
  carbon_black: { label: 'Carbon Black', icon: '⬛', category: 'EDR' },
  // XDR
  cortex_xdr: { label: 'Cortex XDR', icon: '🔶', category: 'XDR' },
  trend_vision_one: { label: 'Trend Vision One', icon: '🔺', category: 'XDR' },
  // Cloud Security
  aws_security_hub: { label: 'AWS Security Hub', icon: '🟠', category: 'Cloud Security' },
  aws_guardduty: { label: 'AWS GuardDuty', icon: '🟠', category: 'Cloud Security' },
  gcp_scc: { label: 'GCP Security Command Center', icon: '🔵', category: 'Cloud Security' },
  azure_defender: { label: 'Azure Defender', icon: '🔷', category: 'Cloud Security' },
  wiz: { label: 'Wiz', icon: '💎', category: 'Cloud Security' },
  orca: { label: 'Orca', icon: '🐋', category: 'Cloud Security' },
  // Identity
  okta: { label: 'Okta', icon: '🔐', category: 'Identity' },
  entra_id: { label: 'Microsoft Entra ID', icon: '🔷', category: 'Identity' },
  azure_ad_identity: { label: 'Azure AD Identity Protection', icon: '🔷', category: 'Identity' },
  crowdstrike_identity: { label: 'CrowdStrike Identity', icon: '🔴', category: 'Identity' },
  // Email Security
  proofpoint: { label: 'Proofpoint', icon: '📧', category: 'Email Security' },
  mimecast: { label: 'Mimecast', icon: '📨', category: 'Email Security' },
  microsoft_defender_email: { label: 'Defender for Office 365', icon: '📬', category: 'Email Security' },
  // Network Security
  cloudflare: { label: 'Cloudflare', icon: '🟠', category: 'Network' },
  darktrace: { label: 'Darktrace', icon: '🌐', category: 'Network' },
  vectra: { label: 'Vectra', icon: '📡', category: 'Network' },
  // Action Connectors
  jira: { label: 'Jira', icon: '📋' },
  slack: { label: 'Slack', icon: '💬' },
  pagerduty: { label: 'PagerDuty', icon: '📟' },
  teams: { label: 'Microsoft Teams', icon: '👥' },
  crowdstrike: { label: 'CrowdStrike (Actions)', icon: <img src="/icons/crowdstrike.png" alt="CrowdStrike" className="w-7 h-7 object-contain" /> },
  sentinelone_action: { label: 'SentinelOne (Actions)', icon: '🛡️' },
  servicenow: { label: 'ServiceNow', icon: '🎫' },
  webhook: { label: 'Webhook', icon: '🔗' },
  http: { label: 'HTTP', icon: '🌐' },
}

export default function ConnectorsPage() {
  const [activeTab, setActiveTab] = useState<ConnectorCategory | 'all'>('all')
  const [filterStatus, setFilterStatus] = useState<ConnectorStatus | ''>('')

  const { data: connectors, isLoading, refetch } = useListConnectorsQuery({
    category: activeTab !== 'all' ? activeTab : undefined,
    status: filterStatus || undefined,
  })
  const [deleteConnector] = useDeleteConnectorMutation()
  const [testConnector, { isLoading: isTesting }] = useTestConnectorMutation()
  const [syncConnector, { isLoading: isSyncing }] = useSyncConnectorMutation()

  const handleDelete = async (id: string, name: string) => {
    if (confirm(`Are you sure you want to delete connector "${name}"?`)) {
      await deleteConnector(id)
    }
  }

  const handleTest = async (id: string) => {
    try {
      const result = await testConnector(id).unwrap()
      alert(result.success ? `Connection successful: ${result.message}` : `Connection failed: ${result.message}`)
    } catch (err) {
      alert('Failed to test connection')
    }
  }

  const handleSync = async (id: string, fullSync: boolean = false) => {
    try {
      const result = await syncConnector({ id, fullSync }).unwrap()
      alert(fullSync
        ? `Full sync queued. Alerts will be fetched from the last 30 days.`
        : `Sync queued. New alerts will be fetched.`
      )
    } catch (err) {
      alert('Failed to sync alerts')
    }
  }

  const dataSourceConnectors = connectors?.items.filter(c => c.category === 'data_source') || []
  const actionConnectors = connectors?.items.filter(c => c.category === 'action') || []

  // Group data sources by their type category (SIEM, EDR, etc.)
  const groupedDataSources = dataSourceConnectors.reduce((acc, connector) => {
    const typeInfo = connectorTypeLabels[connector.connector_type]
    const category = typeInfo?.category || 'Other'
    if (!acc[category]) {
      acc[category] = []
    }
    acc[category].push(connector)
    return acc
  }, {} as Record<string, typeof dataSourceConnectors>)

  // Define category order for display
  const categoryOrder = ['SIEM', 'EDR', 'XDR', 'Cloud Security', 'Identity', 'Email Security', 'Network', 'Other']
  const sortedCategories = Object.keys(groupedDataSources).sort(
    (a, b) => categoryOrder.indexOf(a) - categoryOrder.indexOf(b)
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Connectors</h1>
          <p className="text-muted-foreground">
            Connect to data sources and action platforms
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-4 py-2 bg-muted text-muted-foreground rounded-md font-medium hover:bg-accent"
          >
            <RefreshCw size={18} className={isLoading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <Link
            to="/connectors/new"
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90"
          >
            <Plus size={18} />
            Add Connector
          </Link>
        </div>
      </div>

      {/* Category Tabs */}
      <div className="flex gap-4 border-b">
        <button
          onClick={() => setActiveTab('all')}
          className={cn(
            'px-4 py-2 font-medium border-b-2 transition-colors -mb-[1px]',
            activeTab === 'all'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          All Connectors
        </button>
        <button
          onClick={() => setActiveTab('data_source')}
          className={cn(
            'flex items-center gap-2 px-4 py-2 font-medium border-b-2 transition-colors -mb-[1px]',
            activeTab === 'data_source'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          <Database size={18} />
          Data Sources ({dataSourceConnectors.length})
        </button>
        <button
          onClick={() => setActiveTab('action')}
          className={cn(
            'flex items-center gap-2 px-4 py-2 font-medium border-b-2 transition-colors -mb-[1px]',
            activeTab === 'action'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          <Zap size={18} />
          Action Connectors ({actionConnectors.length})
        </button>
      </div>

      {/* Status Filters */}
      <div className="flex gap-2">
        <button
          onClick={() => setFilterStatus('')}
          className={cn(
            'px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
            filterStatus === '' ? 'bg-primary text-primary-foreground' : 'bg-muted hover:bg-accent'
          )}
        >
          All
        </button>
        {(['connected', 'error', 'disabled', 'pending'] as const).map((status) => (
          <button
            key={status}
            onClick={() => setFilterStatus(status)}
            className={cn(
              'px-3 py-1.5 rounded-md text-sm font-medium transition-colors capitalize',
              filterStatus === status ? 'bg-primary text-primary-foreground' : 'bg-muted hover:bg-accent'
            )}
          >
            {statusConfig[status].label}
          </button>
        ))}
      </div>

      {/* Connectors List */}
      {isLoading ? (
        <div className="rounded-lg border bg-background p-6 text-center text-muted-foreground">
          Loading connectors...
        </div>
      ) : connectors?.items.length === 0 ? (
        <div className="rounded-lg border bg-background p-12 text-center text-muted-foreground">
          <Settings size={48} className="mx-auto mb-4 opacity-20" />
          <p>No connectors configured</p>
          <p className="text-sm mt-2">Add a connector to start ingesting alerts or executing actions</p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Data Sources - Grouped by Category */}
          {(activeTab === 'all' || activeTab === 'data_source') && sortedCategories.length > 0 && (
            <div className="space-y-4">
              {activeTab === 'all' && (
                <h2 className="text-lg font-semibold flex items-center gap-2">
                  <Database size={20} />
                  Data Sources
                </h2>
              )}
              {sortedCategories.map((category) => (
                <div key={category} className="rounded-lg border bg-background overflow-hidden">
                  <div className="px-4 py-2 bg-muted/50 border-b">
                    <h3 className="font-medium text-sm text-muted-foreground">{category}</h3>
                  </div>
                  <div className="divide-y">
                    {groupedDataSources[category].map((connector) => {
                      const typeInfo = connectorTypeLabels[connector.connector_type] || {
                        label: connector.connector_type,
                        icon: '📦',
                      }
                      const StatusIcon = statusConfig[connector.status].icon

                      return (
                        <div key={connector.id} className="p-4 hover:bg-muted/50">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center gap-3 mb-1">
                                {typeof typeInfo.icon === 'string' ? (
                                  <span className="text-2xl">{typeInfo.icon}</span>
                                ) : (
                                  <span className="flex items-center justify-center">{typeInfo.icon}</span>
                                )}
                                <div>
                                  <div className="flex items-center gap-2">
                                    <Link
                                      to={`/connectors/${connector.id}`}
                                      className="font-semibold hover:underline"
                                    >
                                      {connector.name}
                                    </Link>
                                    <span
                                      className={cn(
                                        'flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium',
                                        statusConfig[connector.status].color
                                      )}
                                    >
                                      <StatusIcon size={12} />
                                      {statusConfig[connector.status].label}
                                    </span>
                                  </div>
                                  <p className="text-sm text-muted-foreground">{typeInfo.label}</p>
                                </div>
                              </div>
                              {connector.description && (
                                <p className="text-sm text-muted-foreground ml-11 mb-2">
                                  {connector.description}
                                </p>
                              )}
                              <div className="ml-11 flex items-center gap-4 text-xs text-muted-foreground">
                                {connector.last_health_check && (
                                  <span>
                                    Last checked: {formatDistanceToNow(new Date(connector.last_health_check), { addSuffix: true })}
                                  </span>
                                )}
                                <span>
                                  Sync: {connector.sync_enabled ? `Every ${connector.sync_interval_minutes}m` : 'Disabled'}
                                </span>
                                {connector.last_sync_at && (
                                  <span>
                                    Last sync: {formatDistanceToNow(new Date(connector.last_sync_at), { addSuffix: true })}
                                  </span>
                                )}
                                {connector.last_error && (
                                  <span className="text-red-400">Error: {connector.last_error}</span>
                                )}
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => handleTest(connector.id)}
                                disabled={isTesting}
                                className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                                title="Test Connection"
                              >
                                <Play size={18} />
                              </button>
                              {connector.sync_enabled && (
                                <>
                                  <button
                                    onClick={() => handleSync(connector.id, false)}
                                    disabled={isSyncing}
                                    className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                                    title="Sync New Alerts"
                                  >
                                    <RefreshCw size={18} className={isSyncing ? 'animate-spin' : ''} />
                                  </button>
                                  <button
                                    onClick={() => handleSync(connector.id, true)}
                                    disabled={isSyncing}
                                    className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-primary"
                                    title="Full Resync (Last 30 Days)"
                                  >
                                    <RotateCcw size={18} className={isSyncing ? 'animate-spin' : ''} />
                                  </button>
                                </>
                              )}
                              <Link
                                to={`/connectors/${connector.id}/edit`}
                                className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                                title="Edit"
                              >
                                <Edit2 size={18} />
                              </Link>
                              <button
                                onClick={() => handleDelete(connector.id, connector.name)}
                                className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-destructive"
                                title="Delete"
                              >
                                <Trash2 size={18} />
                              </button>
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Action Connectors */}
          {(activeTab === 'all' || activeTab === 'action') && actionConnectors.length > 0 && (
            <div className="space-y-4">
              {activeTab === 'all' && (
                <h2 className="text-lg font-semibold flex items-center gap-2">
                  <Zap size={20} />
                  Action Connectors
                </h2>
              )}
              <div className="rounded-lg border bg-background overflow-hidden">
                <div className="divide-y">
                  {actionConnectors.map((connector) => {
                    const typeInfo = connectorTypeLabels[connector.connector_type] || {
                      label: connector.connector_type,
                      icon: '📦',
                    }
                    const StatusIcon = statusConfig[connector.status].icon

                    return (
                      <div key={connector.id} className="p-4 hover:bg-muted/50">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-1">
                              {typeof typeInfo.icon === 'string' ? (
                                <span className="text-2xl">{typeInfo.icon}</span>
                              ) : (
                                <span className="flex items-center justify-center">{typeInfo.icon}</span>
                              )}
                              <div>
                                <div className="flex items-center gap-2">
                                  <Link
                                    to={`/connectors/${connector.id}`}
                                    className="font-semibold hover:underline"
                                  >
                                    {connector.name}
                                  </Link>
                                  <span
                                    className={cn(
                                      'flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium',
                                      statusConfig[connector.status].color
                                    )}
                                  >
                                    <StatusIcon size={12} />
                                    {statusConfig[connector.status].label}
                                  </span>
                                </div>
                                <p className="text-sm text-muted-foreground">{typeInfo.label}</p>
                              </div>
                            </div>
                            {connector.description && (
                              <p className="text-sm text-muted-foreground ml-11 mb-2">
                                {connector.description}
                              </p>
                            )}
                            <div className="ml-11 flex items-center gap-4 text-xs text-muted-foreground">
                              {connector.last_health_check && (
                                <span>
                                  Last checked: {formatDistanceToNow(new Date(connector.last_health_check), { addSuffix: true })}
                                </span>
                              )}
                              {connector.last_error && (
                                <span className="text-red-400">Error: {connector.last_error}</span>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleTest(connector.id)}
                              disabled={isTesting}
                              className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                              title="Test Connection"
                            >
                              <Play size={18} />
                            </button>
                            <Link
                              to={`/connectors/${connector.id}/edit`}
                              className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                              title="Edit"
                            >
                              <Edit2 size={18} />
                            </Link>
                            <button
                              onClick={() => handleDelete(connector.id, connector.name)}
                              className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-destructive"
                              title="Delete"
                            >
                              <Trash2 size={18} />
                            </button>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
