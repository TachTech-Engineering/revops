import { useState } from 'react'
import {
  Mail,
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
  Bell,
  Clock,
  Filter,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface EmailConfig {
  smtpHost: string
  smtpPort: number
  username: string
  useTLS: boolean
  fromAddress: string
  fromName: string
  isConnected: boolean
}

interface EmailRule {
  id: string
  name: string
  recipients: string[]
  alertTypes: string[]
  severities: string[]
  schedule: 'immediate' | 'digest_hourly' | 'digest_daily'
  isActive: boolean
  lastSentAt?: string
}

const mockConfig: EmailConfig = {
  smtpHost: 'smtp.company.com',
  smtpPort: 587,
  username: 'alerts@company.com',
  useTLS: true,
  fromAddress: 'alerts@company.com',
  fromName: 'Security Alerts',
  isConnected: true,
}

const mockRules: EmailRule[] = [
  {
    id: '1',
    name: 'Critical Alert Notifications',
    recipients: ['soc-team@company.com', 'security-leads@company.com'],
    alertTypes: ['all'],
    severities: ['critical'],
    schedule: 'immediate',
    isActive: true,
    lastSentAt: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
  },
  {
    id: '2',
    name: 'Daily Security Digest',
    recipients: ['security-team@company.com'],
    alertTypes: ['all'],
    severities: ['high', 'medium'],
    schedule: 'digest_daily',
    isActive: true,
    lastSentAt: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: '3',
    name: 'Compliance Alerts',
    recipients: ['compliance@company.com'],
    alertTypes: ['compliance'],
    severities: ['all'],
    schedule: 'immediate',
    isActive: false,
  },
]

export default function EmailIntegrationPage() {
  const [config, setConfig] = useState(mockConfig)
  const [rules, setRules] = useState(mockRules)
  const [showConfigModal, setShowConfigModal] = useState(false)
  const [showRuleModal, setShowRuleModal] = useState(false)
  const [isTesting, setIsTesting] = useState(false)

  const [newRule, setNewRule] = useState({
    name: '',
    recipients: '',
    alertTypes: [] as string[],
    severities: [] as string[],
    schedule: 'immediate' as const,
  })

  const handleTestConnection = async () => {
    setIsTesting(true)
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setIsTesting(false)
  }

  const handleToggleRule = (ruleId: string) => {
    setRules(
      rules.map((r) =>
        r.id === ruleId ? { ...r, isActive: !r.isActive } : r
      )
    )
  }

  const handleDeleteRule = (ruleId: string) => {
    if (confirm('Are you sure you want to delete this rule?')) {
      setRules(rules.filter((r) => r.id !== ruleId))
    }
  }

  const handleAddRule = () => {
    const rule: EmailRule = {
      id: Date.now().toString(),
      name: newRule.name,
      recipients: newRule.recipients.split(',').map((e) => e.trim()),
      alertTypes: newRule.alertTypes,
      severities: newRule.severities,
      schedule: newRule.schedule,
      isActive: true,
    }
    setRules([...rules, rule])
    setNewRule({ name: '', recipients: '', alertTypes: [], severities: [], schedule: 'immediate' })
    setShowRuleModal(false)
  }

  const getScheduleLabel = (schedule: string) => {
    switch (schedule) {
      case 'immediate':
        return 'Immediate'
      case 'digest_hourly':
        return 'Hourly Digest'
      case 'digest_daily':
        return 'Daily Digest'
      default:
        return schedule
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Mail className="text-primary" />
            Email Integration
          </h1>
          <p className="text-muted-foreground mt-1">
            Configure email notifications for alerts and reports
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowConfigModal(true)}
            className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-accent"
          >
            <Settings size={16} />
            SMTP Settings
          </button>
          <button
            onClick={() => setShowRuleModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            <Plus size={16} />
            Add Rule
          </button>
        </div>
      </div>

      {/* Connection Status */}
      <div className="bg-card rounded-lg border p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-primary/20 flex items-center justify-center">
              <Mail className="text-primary" size={24} />
            </div>
            <div>
              <h3 className="font-semibold">SMTP Server</h3>
              <p className="text-sm text-muted-foreground font-mono">
                {config.smtpHost}:{config.smtpPort} {config.useTLS && '(TLS)'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-muted-foreground">
              From: {config.fromName} &lt;{config.fromAddress}&gt;
            </span>
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

      {/* Email Rules */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold">Notification Rules</h2>
        {rules.map((rule) => (
          <div key={rule.id} className="bg-card rounded-lg border p-4">
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center">
                  <Bell size={18} className="text-muted-foreground" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold">{rule.name}</h3>
                    {rule.isActive ? (
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">
                        Active
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 bg-muted text-muted-foreground text-xs rounded">
                        Inactive
                      </span>
                    )}
                    <span className="px-2 py-0.5 bg-primary/20 text-primary text-xs rounded flex items-center gap-1">
                      <Clock size={10} />
                      {getScheduleLabel(rule.schedule)}
                    </span>
                  </div>
                  <div className="mt-2 space-y-1 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Users size={14} />
                      <span>{rule.recipients.join(', ')}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Filter size={14} />
                      <span>
                        Types: {rule.alertTypes.includes('all') ? 'All' : rule.alertTypes.join(', ')}
                        {' | '}
                        Severities: {rule.severities.includes('all') ? 'All' : rule.severities.join(', ')}
                      </span>
                    </div>
                    {rule.lastSentAt && (
                      <div className="flex items-center gap-2 text-xs">
                        <Clock size={12} />
                        Last sent: {new Date(rule.lastSentAt).toLocaleString()}
                      </div>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleToggleRule(rule.id)}
                  className={cn(
                    'px-3 py-1.5 text-sm rounded-md',
                    rule.isActive
                      ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
                      : 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                  )}
                >
                  {rule.isActive ? 'Disable' : 'Enable'}
                </button>
                <button className="p-2 hover:bg-accent rounded-md">
                  <Edit size={14} />
                </button>
                <button
                  onClick={() => handleDeleteRule(rule.id)}
                  className="p-2 hover:bg-accent rounded-md text-red-400"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-card rounded-lg border p-4 text-center">
          <p className="text-2xl font-bold">1,247</p>
          <p className="text-sm text-muted-foreground">Emails Sent (30d)</p>
        </div>
        <div className="bg-card rounded-lg border p-4 text-center">
          <p className="text-2xl font-bold">98.5%</p>
          <p className="text-sm text-muted-foreground">Delivery Rate</p>
        </div>
        <div className="bg-card rounded-lg border p-4 text-center">
          <p className="text-2xl font-bold">{rules.filter((r) => r.isActive).length}</p>
          <p className="text-sm text-muted-foreground">Active Rules</p>
        </div>
        <div className="bg-card rounded-lg border p-4 text-center">
          <p className="text-2xl font-bold">
            {new Set(rules.flatMap((r) => r.recipients)).size}
          </p>
          <p className="text-sm text-muted-foreground">Recipients</p>
        </div>
      </div>

      {/* SMTP Configuration Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-lg w-full mx-4">
            <h2 className="text-xl font-semibold mb-4">SMTP Configuration</h2>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">SMTP Host</label>
                  <input
                    type="text"
                    defaultValue={config.smtpHost}
                    placeholder="smtp.company.com"
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Port</label>
                  <input
                    type="number"
                    defaultValue={config.smtpPort}
                    placeholder="587"
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Username</label>
                <input
                  type="text"
                  defaultValue={config.username}
                  placeholder="user@company.com"
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
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">From Address</label>
                  <input
                    type="email"
                    defaultValue={config.fromAddress}
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">From Name</label>
                  <input
                    type="text"
                    defaultValue={config.fromName}
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  />
                </div>
              </div>
              <label className="flex items-center gap-2">
                <input type="checkbox" defaultChecked={config.useTLS} className="rounded" />
                <span className="text-sm">Use TLS encryption</span>
              </label>
              <button
                onClick={handleTestConnection}
                disabled={isTesting}
                className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-accent disabled:opacity-50"
              >
                {isTesting ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" />
                    Sending test email...
                  </>
                ) : (
                  <>
                    <TestTube size={14} />
                    Send Test Email
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

      {/* Add Rule Modal */}
      {showRuleModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-lg w-full mx-4">
            <h2 className="text-xl font-semibold mb-4">Add Notification Rule</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Rule Name</label>
                <input
                  type="text"
                  value={newRule.name}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  placeholder="e.g., Critical Alert Notifications"
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Recipients</label>
                <input
                  type="text"
                  value={newRule.recipients}
                  onChange={(e) => setNewRule({ ...newRule, recipients: e.target.value })}
                  placeholder="email1@company.com, email2@company.com"
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Separate multiple emails with commas
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Schedule</label>
                <select
                  value={newRule.schedule}
                  onChange={(e) => setNewRule({ ...newRule, schedule: e.target.value as typeof newRule.schedule })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                >
                  <option value="immediate">Immediate</option>
                  <option value="digest_hourly">Hourly Digest</option>
                  <option value="digest_daily">Daily Digest</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severities</label>
                <div className="flex flex-wrap gap-2">
                  {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
                    <label key={sev} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={newRule.severities.includes(sev)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setNewRule({ ...newRule, severities: [...newRule.severities, sev] })
                          } else {
                            setNewRule({
                              ...newRule,
                              severities: newRule.severities.filter((s) => s !== sev),
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
                onClick={() => setShowRuleModal(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleAddRule}
                disabled={!newRule.name || !newRule.recipients}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                <Save size={14} />
                Add Rule
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
