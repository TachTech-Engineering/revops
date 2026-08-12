import { useState } from 'react'
import {
  AlertCircle,
  Plus,
  Trash2,
  Edit,
  CheckCircle,
  XCircle,
  RefreshCw,
  Settings,
  TestTube,
  Save,
  Users,
  Clock,
  Zap,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface OpsGenieConfig {
  apiKey: string
  region: 'us' | 'eu'
  isConnected: boolean
  lastSyncAt?: string
}

interface OpsGenieTeam {
  id: string
  name: string
  alertSeverities: string[]
  priority: string
  tags: string[]
  autoAcknowledge: boolean
  isActive: boolean
}

const mockConfig: OpsGenieConfig = {
  apiKey: '••••••••-••••-••••-••••-••••••••••••',
  region: 'us',
  isConnected: true,
  lastSyncAt: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
}

const mockTeams: OpsGenieTeam[] = [
  {
    id: '1',
    name: 'Security Operations',
    alertSeverities: ['critical', 'high'],
    priority: 'P1',
    tags: ['security', 'soc'],
    autoAcknowledge: false,
    isActive: true,
  },
  {
    id: '2',
    name: 'Infrastructure Team',
    alertSeverities: ['critical'],
    priority: 'P2',
    tags: ['infrastructure', 'network'],
    autoAcknowledge: false,
    isActive: true,
  },
  {
    id: '3',
    name: 'Compliance Team',
    alertSeverities: ['high', 'medium'],
    priority: 'P3',
    tags: ['compliance', 'audit'],
    autoAcknowledge: true,
    isActive: false,
  },
]

const mockRecentAlerts = [
  {
    id: 'OG-12345',
    message: 'Critical: Multiple failed login attempts detected',
    priority: 'P1',
    status: 'open',
    team: 'Security Operations',
    created: '15 minutes ago',
  },
  {
    id: 'OG-12344',
    message: 'High: Suspicious outbound traffic detected',
    priority: 'P2',
    status: 'acknowledged',
    team: 'Security Operations',
    created: '2 hours ago',
  },
  {
    id: 'OG-12343',
    message: 'Medium: Policy violation detected',
    priority: 'P3',
    status: 'closed',
    team: 'Compliance Team',
    created: '1 day ago',
  },
]

export default function OpsGenieIntegrationPage() {
  const [config, setConfig] = useState(mockConfig)
  const [teams, setTeams] = useState(mockTeams)
  const [showConfigModal, setShowConfigModal] = useState(false)
  const [showTeamModal, setShowTeamModal] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [isSyncing, setIsSyncing] = useState(false)

  const [newTeam, setNewTeam] = useState({
    name: '',
    alertSeverities: [] as string[],
    priority: 'P2',
    tags: '',
  })

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

  const handleToggleTeam = (teamId: string) => {
    setTeams(
      teams.map((t) =>
        t.id === teamId ? { ...t, isActive: !t.isActive } : t
      )
    )
  }

  const handleDeleteTeam = (teamId: string) => {
    if (confirm('Are you sure you want to delete this team mapping?')) {
      setTeams(teams.filter((t) => t.id !== teamId))
    }
  }

  const handleAddTeam = () => {
    const team: OpsGenieTeam = {
      id: Date.now().toString(),
      name: newTeam.name,
      alertSeverities: newTeam.alertSeverities,
      priority: newTeam.priority,
      tags: newTeam.tags.split(',').map((t) => t.trim()).filter(Boolean),
      autoAcknowledge: false,
      isActive: true,
    }
    setTeams([...teams, team])
    setNewTeam({ name: '', alertSeverities: [], priority: 'P2', tags: '' })
    setShowTeamModal(false)
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'P1':
        return 'bg-red-500/20 text-red-400'
      case 'P2':
        return 'bg-orange-500/20 text-orange-400'
      case 'P3':
        return 'bg-yellow-500/20 text-yellow-400'
      case 'P4':
        return 'bg-blue-500/20 text-blue-400'
      default:
        return 'bg-muted text-muted-foreground'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open':
        return 'bg-red-500/20 text-red-400'
      case 'acknowledged':
        return 'bg-yellow-500/20 text-yellow-400'
      case 'closed':
        return 'bg-green-500/20 text-green-400'
      default:
        return 'bg-muted text-muted-foreground'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <AlertCircle className="text-[#0052CC]" />
            OpsGenie Integration
          </h1>
          <p className="text-muted-foreground mt-1">
            Send alerts to OpsGenie for on-call management and escalation
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
                Sync Teams
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
            <div className="w-12 h-12 rounded-lg bg-[#0052CC]/20 flex items-center justify-center">
              <AlertCircle className="text-[#0052CC]" size={24} />
            </div>
            <div>
              <h3 className="font-semibold">OpsGenie</h3>
              <p className="text-sm text-muted-foreground">
                Region: {config.region.toUpperCase()} | API Key configured
              </p>
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
        {/* Team Mappings */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Team Mappings</h2>
            <button
              onClick={() => setShowTeamModal(true)}
              className="flex items-center gap-1 text-sm text-primary hover:underline"
            >
              <Plus size={14} />
              Add Team
            </button>
          </div>
          {teams.map((team) => (
            <div key={team.id} className="bg-card rounded-lg border p-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <Users size={16} className="text-muted-foreground" />
                    <h3 className="font-medium">{team.name}</h3>
                    {team.isActive ? (
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
                        {team.alertSeverities.map((sev) => (
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
                    <div className="flex items-center gap-2">
                      <span>Priority:</span>
                      <span className={cn('px-1.5 py-0.5 rounded text-xs', getPriorityColor(team.priority))}>
                        {team.priority}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span>Tags:</span>
                      <div className="flex gap-1">
                        {team.tags.map((tag) => (
                          <span key={tag} className="px-1.5 py-0.5 bg-muted rounded text-xs">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                    {team.autoAcknowledge && (
                      <div className="flex items-center gap-1 text-yellow-400">
                        <Zap size={12} />
                        Auto-acknowledge enabled
                      </div>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleToggleTeam(team.id)}
                    className={cn(
                      'px-3 py-1 text-xs rounded',
                      team.isActive
                        ? 'bg-red-500/20 text-red-400'
                        : 'bg-green-500/20 text-green-400'
                    )}
                  >
                    {team.isActive ? 'Disable' : 'Enable'}
                  </button>
                  <button className="p-1 hover:bg-accent rounded">
                    <Edit size={14} />
                  </button>
                  <button
                    onClick={() => handleDeleteTeam(team.id)}
                    className="p-1 hover:bg-accent rounded text-red-400"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Recent OpsGenie Alerts */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Recent OpsGenie Alerts</h2>
          <div className="space-y-3">
            {mockRecentAlerts.map((alert) => (
              <div key={alert.id} className="bg-card rounded-lg border p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={cn('px-1.5 py-0.5 rounded text-xs', getPriorityColor(alert.priority))}>
                        {alert.priority}
                      </span>
                      <span className={cn('px-1.5 py-0.5 rounded text-xs capitalize', getStatusColor(alert.status))}>
                        {alert.status}
                      </span>
                    </div>
                    <p className="mt-2 text-sm font-medium">{alert.message}</p>
                    <div className="mt-1 flex items-center gap-4 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Users size={12} />
                        {alert.team}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock size={12} />
                        {alert.created}
                      </span>
                    </div>
                  </div>
                  <a href="#" className="text-primary text-sm hover:underline">
                    {alert.id}
                  </a>
                </div>
              </div>
            ))}
          </div>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-card rounded-lg border p-4 text-center">
              <p className="text-2xl font-bold">89</p>
              <p className="text-sm text-muted-foreground">Alerts (30d)</p>
            </div>
            <div className="bg-card rounded-lg border p-4 text-center">
              <p className="text-2xl font-bold">4.5m</p>
              <p className="text-sm text-muted-foreground">Avg Ack Time</p>
            </div>
            <div className="bg-card rounded-lg border p-4 text-center">
              <p className="text-2xl font-bold">98%</p>
              <p className="text-sm text-muted-foreground">SLA Met</p>
            </div>
          </div>
        </div>
      </div>

      {/* Configuration Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-lg w-full mx-4">
            <h2 className="text-xl font-semibold mb-4">OpsGenie Configuration</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">API Key</label>
                <input
                  type="password"
                  defaultValue={config.apiKey}
                  placeholder="Enter your OpsGenie API key"
                  className="w-full px-3 py-2 bg-background border rounded-md font-mono"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Get your API key from OpsGenie Settings &gt; API Key Management
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Region</label>
                <select
                  defaultValue={config.region}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                >
                  <option value="us">United States (api.opsgenie.com)</option>
                  <option value="eu">Europe (api.eu.opsgenie.com)</option>
                </select>
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

      {/* Add Team Modal */}
      {showTeamModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-lg w-full mx-4">
            <h2 className="text-xl font-semibold mb-4">Add Team Mapping</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">OpsGenie Team</label>
                <input
                  type="text"
                  value={newTeam.name}
                  onChange={(e) => setNewTeam({ ...newTeam, name: e.target.value })}
                  placeholder="Team name in OpsGenie"
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Alert Severities</label>
                <div className="flex flex-wrap gap-2">
                  {['critical', 'high', 'medium', 'low'].map((sev) => (
                    <label key={sev} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={newTeam.alertSeverities.includes(sev)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setNewTeam({
                              ...newTeam,
                              alertSeverities: [...newTeam.alertSeverities, sev],
                            })
                          } else {
                            setNewTeam({
                              ...newTeam,
                              alertSeverities: newTeam.alertSeverities.filter((s) => s !== sev),
                            })
                          }
                        }}
                        className="rounded"
                      />
                      <span className="text-sm capitalize">{sev}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">OpsGenie Priority</label>
                <select
                  value={newTeam.priority}
                  onChange={(e) => setNewTeam({ ...newTeam, priority: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                >
                  <option value="P1">P1 - Critical</option>
                  <option value="P2">P2 - High</option>
                  <option value="P3">P3 - Moderate</option>
                  <option value="P4">P4 - Low</option>
                  <option value="P5">P5 - Informational</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Tags</label>
                <input
                  type="text"
                  value={newTeam.tags}
                  onChange={(e) => setNewTeam({ ...newTeam, tags: e.target.value })}
                  placeholder="security, soc, alerts"
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Separate multiple tags with commas
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowTeamModal(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleAddTeam}
                disabled={!newTeam.name || newTeam.alertSeverities.length === 0}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                <Save size={14} />
                Add Team
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
