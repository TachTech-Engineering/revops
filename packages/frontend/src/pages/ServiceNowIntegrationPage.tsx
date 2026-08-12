import { useState } from 'react'
import {
  Ticket,
  Plus,
  Trash2,
  Edit,
  CheckCircle,
  XCircle,
  RefreshCw,
  Settings,
  TestTube,
  Save,
  Clock,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface ServiceNowConfig {
  instanceUrl: string
  username: string
  isConnected: boolean
  lastSyncAt?: string
}

interface TicketMapping {
  id: string
  name: string
  alertSeverity: string[]
  tableName: string
  assignmentGroup: string
  category: string
  priority: string
  autoCreate: boolean
  isActive: boolean
}

const mockConfig: ServiceNowConfig = {
  instanceUrl: 'https://company.service-now.com',
  username: 'api_user',
  isConnected: true,
  lastSyncAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
}

const mockMappings: TicketMapping[] = [
  {
    id: '1',
    name: 'Critical Security Incidents',
    alertSeverity: ['critical'],
    tableName: 'incident',
    assignmentGroup: 'Security Operations',
    category: 'Security',
    priority: '1 - Critical',
    autoCreate: true,
    isActive: true,
  },
  {
    id: '2',
    name: 'High Priority Alerts',
    alertSeverity: ['high'],
    tableName: 'incident',
    assignmentGroup: 'Security Operations',
    category: 'Security',
    priority: '2 - High',
    autoCreate: true,
    isActive: true,
  },
  {
    id: '3',
    name: 'Compliance Issues',
    alertSeverity: ['medium', 'low'],
    tableName: 'problem',
    assignmentGroup: 'Compliance Team',
    category: 'Compliance',
    priority: '3 - Moderate',
    autoCreate: false,
    isActive: false,
  },
]

const mockRecentTickets = [
  { number: 'INC0012345', severity: 'Critical', status: 'In Progress', created: '2 hours ago' },
  { number: 'INC0012344', severity: 'High', status: 'Assigned', created: '4 hours ago' },
  { number: 'INC0012343', severity: 'High', status: 'Resolved', created: '1 day ago' },
]

export default function ServiceNowIntegrationPage() {
  const [config, setConfig] = useState(mockConfig)
  const [mappings, setMappings] = useState(mockMappings)
  const [showConfigModal, setShowConfigModal] = useState(false)
  const [, setShowMappingModal] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [isSyncing, setIsSyncing] = useState(false)

  const handleTestConnection = async () => {
    setIsTesting(true)
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setIsTesting(false)
  }

  const handleSync = async () => {
    setIsSyncing(true)
    await new Promise((resolve) => setTimeout(resolve, 3000))
    setConfig({ ...config, lastSyncAt: new Date().toISOString() })
    setIsSyncing(false)
  }

  const handleToggleMapping = (mappingId: string) => {
    setMappings(
      mappings.map((m) =>
        m.id === mappingId ? { ...m, isActive: !m.isActive } : m
      )
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Ticket className="text-[#81B5A1]" />
            ServiceNow Integration
          </h1>
          <p className="text-muted-foreground mt-1">
            Create and manage tickets in ServiceNow from alerts
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleSync}
            disabled={isSyncing}
            className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-accent disabled:opacity-50"
          >
            {isSyncing ? (
              <>
                <RefreshCw size={16} className="animate-spin" />
                Syncing...
              </>
            ) : (
              <>
                <RefreshCw size={16} />
                Sync Now
              </>
            )}
          </button>
          <button
            onClick={() => setShowConfigModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            <Settings size={16} />
            Configure
          </button>
        </div>
      </div>

      {/* Connection Status */}
      <div className="bg-card rounded-lg border p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-[#81B5A1]/20 flex items-center justify-center">
              <Ticket className="text-[#81B5A1]" size={24} />
            </div>
            <div>
              <h3 className="font-semibold">ServiceNow Instance</h3>
              <p className="text-sm text-muted-foreground font-mono">{config.instanceUrl}</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {config.lastSyncAt && (
              <span className="text-sm text-muted-foreground flex items-center gap-1">
                <Clock size={14} />
                Last sync: {new Date(config.lastSyncAt).toLocaleTimeString()}
              </span>
            )}
            {config.isConnected ? (
              <span className="flex items-center gap-1 px-2 py-1 bg-green-500/20 text-green-400 rounded text-sm">
                <CheckCircle size={14} />
                Connected
              </span>
            ) : (
              <span className="flex items-center gap-1 px-2 py-1 bg-red-500/20 text-red-400 rounded text-sm">
                <XCircle size={14} />
                Disconnected
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Ticket Mappings */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Ticket Mappings</h2>
            <button
              onClick={() => setShowMappingModal(true)}
              className="flex items-center gap-1 text-sm text-primary hover:underline"
            >
              <Plus size={14} />
              Add Mapping
            </button>
          </div>
          {mappings.map((mapping) => (
            <div key={mapping.id} className="bg-card rounded-lg border p-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-medium">{mapping.name}</h3>
                    {mapping.isActive ? (
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">
                        Active
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 bg-muted text-muted-foreground text-xs rounded">
                        Inactive
                      </span>
                    )}
                  </div>
                  <div className="mt-2 space-y-1 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <span>Severities:</span>
                      <div className="flex gap-1">
                        {mapping.alertSeverity.map((sev) => (
                          <span
                            key={sev}
                            className={cn(
                              'px-1.5 py-0.5 rounded text-xs capitalize',
                              sev === 'critical'
                                ? 'bg-red-500/20 text-red-400'
                                : sev === 'high'
                                ? 'bg-orange-500/20 text-orange-400'
                                : 'bg-yellow-500/20 text-yellow-400'
                            )}
                          >
                            {sev}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div>Table: {mapping.tableName}</div>
                    <div>Assignment Group: {mapping.assignmentGroup}</div>
                    <div>Priority: {mapping.priority}</div>
                    {mapping.autoCreate && (
                      <div className="flex items-center gap-1 text-green-400">
                        <CheckCircle size={12} />
                        Auto-create enabled
                      </div>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleToggleMapping(mapping.id)}
                    className={cn(
                      'px-3 py-1 text-xs rounded',
                      mapping.isActive
                        ? 'bg-red-500/20 text-red-400'
                        : 'bg-green-500/20 text-green-400'
                    )}
                  >
                    {mapping.isActive ? 'Disable' : 'Enable'}
                  </button>
                  <button className="p-1 hover:bg-accent rounded">
                    <Edit size={14} />
                  </button>
                  <button className="p-1 hover:bg-accent rounded text-red-400">
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Recent Tickets */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Recent Tickets</h2>
          <div className="bg-card rounded-lg border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-muted-foreground">
                  <th className="text-left p-3">Ticket</th>
                  <th className="text-left p-3">Severity</th>
                  <th className="text-left p-3">Status</th>
                  <th className="text-left p-3">Created</th>
                </tr>
              </thead>
              <tbody>
                {mockRecentTickets.map((ticket) => (
                  <tr key={ticket.number} className="border-b last:border-0">
                    <td className="p-3">
                      <a href="#" className="text-primary hover:underline font-mono">
                        {ticket.number}
                      </a>
                    </td>
                    <td className="p-3">
                      <span
                        className={cn(
                          'px-2 py-0.5 rounded text-xs',
                          ticket.severity === 'Critical'
                            ? 'bg-red-500/20 text-red-400'
                            : 'bg-orange-500/20 text-orange-400'
                        )}
                      >
                        {ticket.severity}
                      </span>
                    </td>
                    <td className="p-3">{ticket.status}</td>
                    <td className="p-3 text-muted-foreground">{ticket.created}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-card rounded-lg border p-4 text-center">
              <p className="text-2xl font-bold">156</p>
              <p className="text-sm text-muted-foreground">Tickets Created</p>
            </div>
            <div className="bg-card rounded-lg border p-4 text-center">
              <p className="text-2xl font-bold">12</p>
              <p className="text-sm text-muted-foreground">Open</p>
            </div>
            <div className="bg-card rounded-lg border p-4 text-center">
              <p className="text-2xl font-bold">4.2h</p>
              <p className="text-sm text-muted-foreground">Avg Resolution</p>
            </div>
          </div>
        </div>
      </div>

      {/* Configuration Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-lg w-full mx-4">
            <h2 className="text-xl font-semibold mb-4">ServiceNow Configuration</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Instance URL</label>
                <input
                  type="text"
                  defaultValue={config.instanceUrl}
                  placeholder="https://company.service-now.com"
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Username</label>
                <input
                  type="text"
                  defaultValue={config.username}
                  placeholder="api_user"
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Password</label>
                <input
                  type="password"
                  placeholder="••••••••"
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <button
                onClick={handleTestConnection}
                disabled={isTesting}
                className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-accent disabled:opacity-50"
              >
                {isTesting ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" />
                    Testing...
                  </>
                ) : (
                  <>
                    <TestTube size={14} />
                    Test Connection
                  </>
                )}
              </button>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowConfigModal(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
                <Save size={14} />
                Save Configuration
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
