import { useState } from 'react'
import {
  MessageSquare,
  Plus,
  Trash2,
  Edit,
  CheckCircle,
  XCircle,
  RefreshCw,
  Settings,
  Bell,
  Hash,
  Link,
  TestTube,
  Save,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface TeamsChannel {
  id: string
  name: string
  webhookUrl: string
  isActive: boolean
  alertTypes: string[]
  severities: string[]
  lastMessageAt?: string
}

const mockChannels: TeamsChannel[] = [
  {
    id: '1',
    name: 'Security Alerts',
    webhookUrl: 'https://outlook.office.com/webhook/xxx/IncomingWebhook/yyy',
    isActive: true,
    alertTypes: ['all'],
    severities: ['critical', 'high'],
    lastMessageAt: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
  },
  {
    id: '2',
    name: 'SOC Team',
    webhookUrl: 'https://outlook.office.com/webhook/aaa/IncomingWebhook/bbb',
    isActive: true,
    alertTypes: ['incident'],
    severities: ['critical', 'high', 'medium'],
    lastMessageAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: '3',
    name: 'Compliance Updates',
    webhookUrl: 'https://outlook.office.com/webhook/ccc/IncomingWebhook/ddd',
    isActive: false,
    alertTypes: ['compliance'],
    severities: ['all'],
  },
]

export default function TeamsIntegrationPage() {
  const [channels, setChannels] = useState(mockChannels)
  const [showAddModal, setShowAddModal] = useState(false)
  const [testingChannel, setTestingChannel] = useState<string | null>(null)
  const [newChannel, setNewChannel] = useState({
    name: '',
    webhookUrl: '',
    alertTypes: [] as string[],
    severities: [] as string[],
  })

  const handleToggleChannel = (channelId: string) => {
    setChannels(
      channels.map((ch) =>
        ch.id === channelId ? { ...ch, isActive: !ch.isActive } : ch
      )
    )
  }

  const handleTestChannel = async (channelId: string) => {
    setTestingChannel(channelId)
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setTestingChannel(null)
  }

  const handleDeleteChannel = (channelId: string) => {
    if (confirm('Are you sure you want to delete this channel?')) {
      setChannels(channels.filter((ch) => ch.id !== channelId))
    }
  }

  const handleAddChannel = () => {
    const channel: TeamsChannel = {
      id: Date.now().toString(),
      name: newChannel.name,
      webhookUrl: newChannel.webhookUrl,
      isActive: true,
      alertTypes: newChannel.alertTypes,
      severities: newChannel.severities,
    }
    setChannels([...channels, channel])
    setNewChannel({ name: '', webhookUrl: '', alertTypes: [], severities: [] })
    setShowAddModal(false)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <MessageSquare className="text-[#6264A7]" />
            Microsoft Teams Integration
          </h1>
          <p className="text-muted-foreground mt-1">
            Send alerts and notifications to Microsoft Teams channels
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
        >
          <Plus size={16} />
          Add Channel
        </button>
      </div>

      {/* Connection Status */}
      <div className="bg-card rounded-lg border p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-[#6264A7]/20 flex items-center justify-center">
              <MessageSquare className="text-[#6264A7]" size={24} />
            </div>
            <div>
              <h3 className="font-semibold">Microsoft Teams</h3>
              <p className="text-sm text-muted-foreground">
                {channels.filter((c) => c.isActive).length} active channels configured
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1 px-2 py-1 bg-green-500/20 text-green-400 rounded text-sm">
              <CheckCircle size={14} />
              Connected
            </span>
          </div>
        </div>
      </div>

      {/* Channels List */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold">Configured Channels</h2>
        {channels.map((channel) => (
          <div key={channel.id} className="bg-card rounded-lg border p-4">
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center">
                  <Hash size={18} className="text-muted-foreground" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold">{channel.name}</h3>
                    {channel.isActive ? (
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">
                        Active
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 bg-muted text-muted-foreground text-xs rounded">
                        Inactive
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground mt-1 font-mono">
                    {channel.webhookUrl.substring(0, 50)}...
                  </p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                    <span>
                      Alert types:{' '}
                      {channel.alertTypes.includes('all')
                        ? 'All'
                        : channel.alertTypes.join(', ')}
                    </span>
                    <span>
                      Severities:{' '}
                      {channel.severities.includes('all')
                        ? 'All'
                        : channel.severities.join(', ')}
                    </span>
                    {channel.lastMessageAt && (
                      <span>
                        Last message: {new Date(channel.lastMessageAt).toLocaleString()}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleTestChannel(channel.id)}
                  disabled={testingChannel === channel.id}
                  className="flex items-center gap-1 px-3 py-1.5 text-sm border rounded-md hover:bg-accent disabled:opacity-50"
                >
                  {testingChannel === channel.id ? (
                    <>
                      <RefreshCw size={14} className="animate-spin" />
                      Testing...
                    </>
                  ) : (
                    <>
                      <TestTube size={14} />
                      Test
                    </>
                  )}
                </button>
                <button
                  onClick={() => handleToggleChannel(channel.id)}
                  className={cn(
                    'px-3 py-1.5 text-sm rounded-md',
                    channel.isActive
                      ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
                      : 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                  )}
                >
                  {channel.isActive ? 'Disable' : 'Enable'}
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
          </div>
        ))}
      </div>

      {/* Add Channel Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-lg w-full mx-4">
            <h2 className="text-xl font-semibold mb-4">Add Teams Channel</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Channel Name</label>
                <input
                  type="text"
                  value={newChannel.name}
                  onChange={(e) => setNewChannel({ ...newChannel, name: e.target.value })}
                  placeholder="e.g., Security Alerts"
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Webhook URL</label>
                <input
                  type="text"
                  value={newChannel.webhookUrl}
                  onChange={(e) => setNewChannel({ ...newChannel, webhookUrl: e.target.value })}
                  placeholder="https://outlook.office.com/webhook/..."
                  className="w-full px-3 py-2 bg-background border rounded-md font-mono text-sm"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Create an Incoming Webhook connector in your Teams channel
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Alert Types</label>
                <div className="flex flex-wrap gap-2">
                  {['all', 'alert', 'incident', 'compliance'].map((type) => (
                    <label key={type} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={newChannel.alertTypes.includes(type)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setNewChannel({
                              ...newChannel,
                              alertTypes: [...newChannel.alertTypes, type],
                            })
                          } else {
                            setNewChannel({
                              ...newChannel,
                              alertTypes: newChannel.alertTypes.filter((t) => t !== type),
                            })
                          }
                        }}
                        className="rounded"
                      />
                      <span className="text-sm capitalize">{type}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severities</label>
                <div className="flex flex-wrap gap-2">
                  {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
                    <label key={sev} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={newChannel.severities.includes(sev)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setNewChannel({
                              ...newChannel,
                              severities: [...newChannel.severities, sev],
                            })
                          } else {
                            setNewChannel({
                              ...newChannel,
                              severities: newChannel.severities.filter((s) => s !== sev),
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
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleAddChannel}
                disabled={!newChannel.name || !newChannel.webhookUrl}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                <Save size={14} />
                Add Channel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Setup Instructions */}
      <div className="bg-card rounded-lg border p-4">
        <h3 className="font-semibold mb-3 flex items-center gap-2">
          <Settings size={16} />
          Setup Instructions
        </h3>
        <ol className="list-decimal list-inside space-y-2 text-sm text-muted-foreground">
          <li>Open Microsoft Teams and navigate to your desired channel</li>
          <li>Click the "..." menu and select "Connectors"</li>
          <li>Find "Incoming Webhook" and click "Configure"</li>
          <li>Give your webhook a name and optionally upload an image</li>
          <li>Copy the webhook URL and paste it above</li>
          <li>Configure which alerts should be sent to this channel</li>
        </ol>
      </div>
    </div>
  )
}
