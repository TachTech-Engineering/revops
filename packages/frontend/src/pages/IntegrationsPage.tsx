import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Plug,
  Search,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ChevronRight,
  Plus,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface Integration {
  id: string
  name: string
  description: string
  category: 'communication' | 'ticketing' | 'oncall' | 'siem' | 'cloud' | 'telephony'
  icon: string
  status: 'connected' | 'disconnected' | 'error'
  lastSync?: string
  configPath: string
}

const integrations: Integration[] = [
  {
    id: 'slack',
    name: 'Slack',
    description: 'Send alerts and notifications to Slack channels',
    category: 'communication',
    icon: '💬',
    status: 'disconnected',
    configPath: '/integrations/slack',
  },
  {
    id: 'teams',
    name: 'Microsoft Teams',
    description: 'Send alerts to Microsoft Teams channels',
    category: 'communication',
    icon: '👥',
    status: 'disconnected',
    configPath: '/integrations/teams',
  },
  {
    id: 'jira',
    name: 'Jira',
    description: 'Create and manage tickets from alerts',
    category: 'ticketing',
    icon: '🎫',
    status: 'disconnected',
    configPath: '/integrations/jira',
  },
  {
    id: 'pagerduty',
    name: 'PagerDuty',
    description: 'Trigger incidents and manage on-call rotations',
    category: 'oncall',
    icon: '🚨',
    status: 'disconnected',
    configPath: '/integrations/pagerduty',
  },
  {
    id: 'servicenow',
    name: 'ServiceNow',
    description: 'Create incidents and manage ITSM workflows',
    category: 'ticketing',
    icon: '🔧',
    status: 'disconnected',
    configPath: '/integrations/servicenow',
  },
  {
    id: 'opsgenie',
    name: 'OpsGenie',
    description: 'Alert management and on-call scheduling',
    category: 'oncall',
    icon: '📟',
    status: 'disconnected',
    configPath: '/integrations/opsgenie',
  },
  {
    id: 'email',
    name: 'Email (SMTP)',
    description: 'Send alerts via email to recipients',
    category: 'communication',
    icon: '📧',
    status: 'disconnected',
    configPath: '/integrations/email',
  },
  {
    id: 'webhook',
    name: 'Custom Webhooks',
    description: 'Send data to custom HTTP endpoints',
    category: 'communication',
    icon: '🔗',
    status: 'disconnected',
    configPath: '/webhooks',
  },
  {
    id: 'fonoster',
    name: 'Telephony (Calls/SMS)',
    description: 'Voice calls and SMS for escalation notifications',
    category: 'telephony',
    icon: '📞',
    status: 'connected',
    configPath: '/integrations/fonoster',
  },
]

const categories = [
  { id: 'all', label: 'All Integrations' },
  { id: 'communication', label: 'Communication' },
  { id: 'telephony', label: 'Telephony' },
  { id: 'ticketing', label: 'Ticketing' },
  { id: 'oncall', label: 'On-Call' },
]

const statusConfig = {
  connected: { icon: CheckCircle, color: 'text-green-400', label: 'Connected' },
  disconnected: { icon: XCircle, color: 'text-gray-400', label: 'Not Connected' },
  error: { icon: AlertTriangle, color: 'text-red-400', label: 'Error' },
}

export default function IntegrationsPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')

  const filteredIntegrations = integrations.filter((integration) => {
    const matchesSearch =
      integration.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      integration.description.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesCategory =
      selectedCategory === 'all' || integration.category === selectedCategory
    return matchesSearch && matchesCategory
  })

  const connectedCount = integrations.filter((i) => i.status === 'connected').length
  const errorCount = integrations.filter((i) => i.status === 'error').length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Plug className="text-primary" />
            Integrations
          </h1>
          <p className="text-muted-foreground mt-1">
            Connect external services to enhance your security operations
          </p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
          <Plus size={16} />
          Add Integration
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-card rounded-lg border p-4">
          <p className="text-sm text-muted-foreground">Total Integrations</p>
          <p className="text-2xl font-bold">{integrations.length}</p>
        </div>
        <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
          <p className="text-sm text-muted-foreground">Connected</p>
          <p className="text-2xl font-bold text-green-400">{connectedCount}</p>
        </div>
        {errorCount > 0 && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
            <p className="text-sm text-muted-foreground">Errors</p>
            <p className="text-2xl font-bold text-red-400">{errorCount}</p>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={16} />
          <input
            type="text"
            placeholder="Search integrations..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-background border rounded-md"
          />
        </div>
        <div className="flex gap-2">
          {categories.map((category) => (
            <button
              key={category.id}
              onClick={() => setSelectedCategory(category.id)}
              className={cn(
                'px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
                selectedCategory === category.id
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-muted hover:bg-muted/80'
              )}
            >
              {category.label}
            </button>
          ))}
        </div>
      </div>

      {/* Integration Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {filteredIntegrations.map((integration) => {
          const status = statusConfig[integration.status]
          const StatusIcon = status.icon
          return (
            <Link
              key={integration.id}
              to={integration.configPath}
              className="bg-card rounded-lg border p-4 hover:border-primary/50 transition-colors group"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{integration.icon}</span>
                  <div>
                    <h3 className="font-semibold group-hover:text-primary transition-colors">
                      {integration.name}
                    </h3>
                    <p className="text-xs text-muted-foreground capitalize">
                      {integration.category}
                    </p>
                  </div>
                </div>
                <StatusIcon size={18} className={status.color} />
              </div>
              <p className="text-sm text-muted-foreground mb-4">
                {integration.description}
              </p>
              <div className="flex items-center justify-between">
                <span className={cn('text-xs flex items-center gap-1', status.color)}>
                  {status.label}
                  {integration.lastSync && integration.status === 'connected' && (
                    <span className="text-muted-foreground">
                      • Synced {new Date(integration.lastSync).toLocaleTimeString()}
                    </span>
                  )}
                </span>
                <ChevronRight size={16} className="text-muted-foreground group-hover:text-primary transition-colors" />
              </div>
            </Link>
          )
        })}
      </div>

      {filteredIntegrations.length === 0 && (
        <div className="text-center py-12">
          <Plug className="mx-auto text-muted-foreground mb-4" size={48} />
          <p className="text-muted-foreground">No integrations found matching your criteria</p>
        </div>
      )}
    </div>
  )
}
