import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowLeft,
  MessageSquare,
  CheckCircle,
  AlertTriangle,
  Plus,
  Trash2,
  Edit,
  RefreshCw,
  TestTube,
  Save,
  Hash,
  Bell,
  Settings,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface SlackChannel {
  id: string
  name: string
  webhookUrl: string
  notificationTypes: string[]
  severityFilter: string[]
  isEnabled: boolean
}

interface NotificationRule {
  id: string
  name: string
  channels: string[]
  conditions: {
    type: string
    value: string
  }[]
  isEnabled: boolean
}

// Mock data
const mockChannels: SlackChannel[] = [
  {
    id: '1',
    name: '#security-alerts',
    webhookUrl: 'https://hooks.slack.com/services/xxx',
    notificationTypes: ['alerts', 'incidents'],
    severityFilter: ['critical', 'high'],
    isEnabled: true,
  },
  {
    id: '2',
    name: '#soc-team',
    webhookUrl: 'https://hooks.slack.com/services/yyy',
    notificationTypes: ['alerts', 'incidents', 'reports'],
    severityFilter: ['critical', 'high', 'medium'],
    isEnabled: true,
  },
  {
    id: '3',
    name: '#security-reports',
    webhookUrl: 'https://hooks.slack.com/services/zzz',
    notificationTypes: ['reports'],
    severityFilter: [],
    isEnabled: false,
  },
]

const mockRules: NotificationRule[] = [
  {
    id: '1',
    name: 'Critical Alert Escalation',
    channels: ['#security-alerts'],
    conditions: [
      { type: 'severity', value: 'critical' },
      { type: 'unassigned_for', value: '15m' },
    ],
    isEnabled: true,
  },
  {
    id: '2',
    name: 'AWS Security Alerts',
    channels: ['#security-alerts', '#soc-team'],
    conditions: [
      { type: 'source', value: 'AWS.CloudTrail' },
      { type: 'severity', value: 'high' },
    ],
    isEnabled: true,
  },
]

export default function SlackIntegrationPage() {
  const [isConnected, setIsConnected] = useState(true)
  const [channels, setChannels] = useState(mockChannels)
  const [rules, setRules] = useState(mockRules)
  const [showAddChannel, setShowAddChannel] = useState(false)
  const [showAddRule, setShowAddRule] = useState(false)
  const [testingChannel, setTestingChannel] = useState<string | null>(null)
  const [isSaving, setIsSaving] = useState(false)

  const [newChannel, setNewChannel] = useState({
    name: '',
    webhookUrl: '',
    notificationTypes: [] as string[],
    severityFilter: [] as string[],
  })

  const handleTestChannel = async (channelId: string) => {
    setTestingChannel(channelId)
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setTestingChannel(null)
  }

  const handleSaveChannel = async () => {
    if (!newChannel.name || !newChannel.webhookUrl) return
    setIsSaving(true)
    await new Promise((resolve) => setTimeout(resolve, 1000))
    setChannels([
      ...channels,
      {
        id: Date.now().toString(),
        ...newChannel,
        isEnabled: true,
      },
    ])
    setNewChannel({ name: '', webhookUrl: '', notificationTypes: [], severityFilter: [] })
    setShowAddChannel(false)
    setIsSaving(false)
  }

  const handleDeleteChannel = (channelId: string) => {
    if (confirm('Are you sure you want to delete this channel?')) {
      setChannels(channels.filter((c) => c.id !== channelId))
    }
  }

  const handleToggleChannel = (channelId: string) => {
    setChannels(
      channels.map((c) => (c.id === channelId ? { ...c, isEnabled: !c.isEnabled } : c))
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link to="/integrations" className="p-2 hover:bg-accent rounded-md">
          <ArrowLeft size={20} />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <MessageSquare className="text-primary" />
            Slack Integration
          </h1>
          <p className="text-muted-foreground">
            Configure Slack channels and notification rules
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isConnected ? (
            <span className="flex items-center gap-2 px-3 py-1.5 bg-green-500/20 text-green-400 rounded-md text-sm">
              <CheckCircle size={14} />
              Connected
            </span>
          ) : (
            <span className="flex items-center gap-2 px-3 py-1.5 bg-yellow-500/20 text-yellow-400 rounded-md text-sm">
              <AlertTriangle size={14} />
              Not Connected
            </span>
          )}
          <button className="px-4 py-2 border rounded-md hover:bg-accent">
            {isConnected ? 'Reconnect' : 'Connect to Slack'}
          </button>
        </div>
      </div>

      {/* Channels Section */}
      <div className="bg-card rounded-lg border">
        <div className="flex items-center justify-between p-4 border-b">
          <div className="flex items-center gap-2">
            <Hash size={18} />
            <h2 className="font-semibold">Slack Channels</h2>
            <span className="text-xs bg-muted px-2 py-0.5 rounded">
              {channels.length} configured
            </span>
          </div>
          <button
            onClick={() => setShowAddChannel(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90"
          >
            <Plus size={14} />
            Add Channel
          </button>
        </div>

        {/* Add Channel Form */}
        {showAddChannel && (
          <div className="p-4 border-b bg-muted/30">
            <h3 className="font-medium mb-4">Add New Channel</h3>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="block text-sm font-medium mb-1">Channel Name</label>
                <input
                  type="text"
                  placeholder="#channel-name"
                  value={newChannel.name}
                  onChange={(e) => setNewChannel({ ...newChannel, name: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Webhook URL</label>
                <input
                  type="text"
                  placeholder="https://hooks.slack.com/services/..."
                  value={newChannel.webhookUrl}
                  onChange={(e) => setNewChannel({ ...newChannel, webhookUrl: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Notification Types</label>
                <div className="flex flex-wrap gap-2">
                  {['alerts', 'incidents', 'reports'].map((type) => (
                    <button
                      key={type}
                      onClick={() =>
                        setNewChannel({
                          ...newChannel,
                          notificationTypes: newChannel.notificationTypes.includes(type)
                            ? newChannel.notificationTypes.filter((t) => t !== type)
                            : [...newChannel.notificationTypes, type],
                        })
                      }
                      className={cn(
                        'px-3 py-1 rounded text-sm capitalize',
                        newChannel.notificationTypes.includes(type)
                          ? 'bg-primary text-primary-foreground'
                          : 'bg-muted'
                      )}
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity Filter</label>
                <div className="flex flex-wrap gap-2">
                  {['critical', 'high', 'medium', 'low'].map((severity) => (
                    <button
                      key={severity}
                      onClick={() =>
                        setNewChannel({
                          ...newChannel,
                          severityFilter: newChannel.severityFilter.includes(severity)
                            ? newChannel.severityFilter.filter((s) => s !== severity)
                            : [...newChannel.severityFilter, severity],
                        })
                      }
                      className={cn(
                        'px-3 py-1 rounded text-sm capitalize',
                        newChannel.severityFilter.includes(severity)
                          ? 'bg-primary text-primary-foreground'
                          : 'bg-muted'
                      )}
                    >
                      {severity}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-4">
              <button
                onClick={() => setShowAddChannel(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveChannel}
                disabled={isSaving || !newChannel.name || !newChannel.webhookUrl}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                {isSaving ? <RefreshCw size={14} className="animate-spin" /> : <Save size={14} />}
                Save Channel
              </button>
            </div>
          </div>
        )}

        {/* Channel List */}
        <div className="divide-y">
          {channels.map((channel) => (
            <div key={channel.id} className="p-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div
                  className={cn(
                    'w-10 h-10 rounded-lg flex items-center justify-center',
                    channel.isEnabled ? 'bg-green-500/20' : 'bg-muted'
                  )}
                >
                  <Hash
                    size={18}
                    className={channel.isEnabled ? 'text-green-400' : 'text-muted-foreground'}
                  />
                </div>
                <div>
                  <p className="font-medium">{channel.name}</p>
                  <div className="flex items-center gap-2 mt-1">
                    {channel.notificationTypes.map((type) => (
                      <span key={type} className="text-xs bg-muted px-2 py-0.5 rounded capitalize">
                        {type}
                      </span>
                    ))}
                    {channel.severityFilter.length > 0 && (
                      <span className="text-xs text-muted-foreground">
                        • {channel.severityFilter.join(', ')} severity
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleTestChannel(channel.id)}
                  disabled={testingChannel === channel.id}
                  className="flex items-center gap-1 px-3 py-1.5 border rounded-md text-sm hover:bg-accent disabled:opacity-50"
                >
                  {testingChannel === channel.id ? (
                    <>
                      <RefreshCw size={12} className="animate-spin" />
                      Testing...
                    </>
                  ) : (
                    <>
                      <TestTube size={12} />
                      Test
                    </>
                  )}
                </button>
                <button
                  onClick={() => handleToggleChannel(channel.id)}
                  className={cn(
                    'px-3 py-1.5 rounded-md text-sm',
                    channel.isEnabled
                      ? 'bg-green-500/20 text-green-400'
                      : 'bg-muted text-muted-foreground'
                  )}
                >
                  {channel.isEnabled ? 'Enabled' : 'Disabled'}
                </button>
                <button className="p-2 hover:bg-accent rounded-md">
                  <Edit size={14} />
                </button>
                <button
                  onClick={() => handleDeleteChannel(channel.id)}
                  className="p-2 hover:bg-accent rounded-md text-red-400"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Notification Rules */}
      <div className="bg-card rounded-lg border">
        <div className="flex items-center justify-between p-4 border-b">
          <div className="flex items-center gap-2">
            <Bell size={18} />
            <h2 className="font-semibold">Notification Rules</h2>
            <span className="text-xs bg-muted px-2 py-0.5 rounded">
              {rules.length} rules
            </span>
          </div>
          <button
            onClick={() => setShowAddRule(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90"
          >
            <Plus size={14} />
            Add Rule
          </button>
        </div>

        <div className="divide-y">
          {rules.map((rule) => (
            <div key={rule.id} className="p-4 flex items-center justify-between">
              <div>
                <p className="font-medium">{rule.name}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xs text-muted-foreground">
                    Channels: {rule.channels.join(', ')}
                  </span>
                  <span className="text-xs text-muted-foreground">•</span>
                  <span className="text-xs text-muted-foreground">
                    {rule.conditions.length} conditions
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    'px-3 py-1.5 rounded-md text-sm',
                    rule.isEnabled
                      ? 'bg-green-500/20 text-green-400'
                      : 'bg-muted text-muted-foreground'
                  )}
                >
                  {rule.isEnabled ? 'Active' : 'Inactive'}
                </span>
                <button className="p-2 hover:bg-accent rounded-md">
                  <Settings size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
