import { useState } from 'react'
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

const statusConfig: Record<ConnectorStatus, { label: string; color: string; icon: typeof CheckCircle }> = {
  connected: { label: 'Connected', color: 'bg-green-500/20 text-green-400', icon: CheckCircle },
  error: { label: 'Error', color: 'bg-red-500/20 text-red-400', icon: XCircle },
  disabled: { label: 'Disabled', color: 'bg-gray-500/20 text-gray-400', icon: Clock },
  pending: { label: 'Pending', color: 'bg-yellow-500/20 text-yellow-400', icon: Clock },
}

const connectorTypeLabels: Record<string, { label: string; icon: string }> = {
  // Data Sources
  panther: { label: 'Panther', icon: '🐆' },
  google_secops: { label: 'Google SecOps', icon: '🔵' },
  splunk: { label: 'Splunk', icon: '🟢' },
  sentinel: { label: 'Microsoft Sentinel', icon: '🔷' },
  elastic: { label: 'Elastic Security', icon: '🟡' },
  // Action Connectors
  jira: { label: 'Jira', icon: '📋' },
  slack: { label: 'Slack', icon: '💬' },
  pagerduty: { label: 'PagerDuty', icon: '📟' },
  teams: { label: 'Microsoft Teams', icon: '👥' },
  crowdstrike: { label: 'CrowdStrike', icon: '🦅' },
  sentinelone: { label: 'SentinelOne', icon: '🛡️' },
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

  const handleSync = async (id: string) => {
    try {
      const result = await syncConnector(id).unwrap()
      alert(`Synced ${result.alerts_new} new alerts, ${result.alerts_updated} updated`)
    } catch (err) {
      alert('Failed to sync alerts')
    }
  }

  const dataSourceConnectors = connectors?.items.filter(c => c.category === 'data_source') || []
  const actionConnectors = connectors?.items.filter(c => c.category === 'action') || []

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
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading connectors...</div>
        ) : connectors?.items.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground">
            <Settings size={48} className="mx-auto mb-4 opacity-20" />
            <p>No connectors configured</p>
            <p className="text-sm mt-2">Add a connector to start ingesting alerts or executing actions</p>
          </div>
        ) : (
          <div className="divide-y">
            {connectors?.items.map((connector) => {
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
                        <span className="text-2xl">{typeInfo.icon}</span>
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
                            <span className="px-2 py-0.5 rounded text-xs font-medium bg-muted">
                              {connector.category === 'data_source' ? 'Data Source' : 'Action'}
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
                        {connector.category === 'data_source' && (
                          <>
                            <span>
                              Sync: {connector.sync_enabled ? `Every ${connector.sync_interval_minutes}m` : 'Disabled'}
                            </span>
                            {connector.last_sync_at && (
                              <span>
                                Last sync: {formatDistanceToNow(new Date(connector.last_sync_at), { addSuffix: true })}
                              </span>
                            )}
                          </>
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
                      {connector.category === 'data_source' && connector.sync_enabled && (
                        <button
                          onClick={() => handleSync(connector.id)}
                          disabled={isSyncing}
                          className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                          title="Sync Alerts"
                        >
                          <RefreshCw size={18} className={isSyncing ? 'animate-spin' : ''} />
                        </button>
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
        )}
      </div>
    </div>
  )
}
