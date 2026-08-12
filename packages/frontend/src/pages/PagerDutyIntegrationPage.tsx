import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowLeft,
  CheckCircle,
  AlertTriangle,
  Plus,
  Trash2,
  Edit,
  RefreshCw,
  Save,
  Settings,
  Bell,
  Users,
  Clock,
  Zap,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface PagerDutyService {
  id: string
  name: string
  integrationKey: string
  escalationPolicy: string
  urgency: 'high' | 'low' | 'dynamic'
  severityMapping: string[]
  isEnabled: boolean
}

// Mock data
const mockServices: PagerDutyService[] = [
  {
    id: '1',
    name: 'Critical Security Alerts',
    integrationKey: 'xxxxxxxxxxxxx',
    escalationPolicy: 'Security On-Call',
    urgency: 'high',
    severityMapping: ['critical'],
    isEnabled: true,
  },
  {
    id: '2',
    name: 'Security Operations',
    integrationKey: 'yyyyyyyyyyyyy',
    escalationPolicy: 'SOC Team',
    urgency: 'dynamic',
    severityMapping: ['critical', 'high'],
    isEnabled: true,
  },
  {
    id: '3',
    name: 'Non-Critical Alerts',
    integrationKey: 'zzzzzzzzzzzzz',
    escalationPolicy: 'General IT',
    urgency: 'low',
    severityMapping: ['medium', 'low'],
    isEnabled: false,
  },
]

export default function PagerDutyIntegrationPage() {
  const [isConnected] = useState(true)
  const [services, setServices] = useState(mockServices)
  const [showAddService, setShowAddService] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [testingService, setTestingService] = useState<string | null>(null)

  const [settings, setSettings] = useState({
    apiKey: '••••••••••••••••',
    accountSubdomain: 'company',
    autoResolve: true,
    includeAlertDetails: true,
    deduplicationKey: 'alert_id',
  })

  const [newService, setNewService] = useState({
    name: '',
    integrationKey: '',
    escalationPolicy: '',
    urgency: 'dynamic' as 'high' | 'low' | 'dynamic',
    severityMapping: [] as string[],
  })

  const handleTestConnection = async () => {
    setIsTesting(true)
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setIsTesting(false)
  }

  const handleTestService = async (serviceId: string) => {
    setTestingService(serviceId)
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setTestingService(null)
  }

  const handleSaveSettings = async () => {
    setIsSaving(true)
    await new Promise((resolve) => setTimeout(resolve, 1000))
    setIsSaving(false)
  }

  const handleAddService = async () => {
    if (!newService.name || !newService.integrationKey) return
    setIsSaving(true)
    await new Promise((resolve) => setTimeout(resolve, 1000))
    setServices([
      ...services,
      {
        id: Date.now().toString(),
        ...newService,
        isEnabled: true,
      },
    ])
    setNewService({
      name: '',
      integrationKey: '',
      escalationPolicy: '',
      urgency: 'dynamic',
      severityMapping: [],
    })
    setShowAddService(false)
    setIsSaving(false)
  }

  const handleToggleService = (serviceId: string) => {
    setServices(
      services.map((s) => (s.id === serviceId ? { ...s, isEnabled: !s.isEnabled } : s))
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
            <Bell className="text-green-500" />
            PagerDuty Integration
          </h1>
          <p className="text-muted-foreground">
            Configure incident alerting and on-call escalations
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
        </div>
      </div>

      {/* Connection Settings */}
      <div className="bg-card rounded-lg border">
        <div className="flex items-center justify-between p-4 border-b">
          <div className="flex items-center gap-2">
            <Settings size={18} />
            <h2 className="font-semibold">Connection Settings</h2>
          </div>
          <button
            onClick={handleTestConnection}
            disabled={isTesting}
            className="flex items-center gap-2 px-3 py-1.5 border rounded-md text-sm hover:bg-accent disabled:opacity-50"
          >
            {isTesting ? (
              <>
                <RefreshCw size={14} className="animate-spin" />
                Testing...
              </>
            ) : (
              'Test Connection'
            )}
          </button>
        </div>

        <div className="p-4 space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-sm font-medium mb-1">API Key</label>
              <input
                type="password"
                value={settings.apiKey}
                onChange={(e) => setSettings({ ...settings, apiKey: e.target.value })}
                placeholder="Your PagerDuty API key"
                className="w-full px-3 py-2 bg-background border rounded-md"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Account Subdomain</label>
              <div className="flex items-center">
                <input
                  type="text"
                  value={settings.accountSubdomain}
                  onChange={(e) => setSettings({ ...settings, accountSubdomain: e.target.value })}
                  placeholder="your-company"
                  className="flex-1 px-3 py-2 bg-background border border-r-0 rounded-l-md"
                />
                <span className="px-3 py-2 bg-muted border rounded-r-md text-sm text-muted-foreground">
                  .pagerduty.com
                </span>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Deduplication Key</label>
              <select
                value={settings.deduplicationKey}
                onChange={(e) => setSettings({ ...settings, deduplicationKey: e.target.value })}
                className="w-full px-3 py-2 bg-background border rounded-md"
              >
                <option value="alert_id">Alert ID</option>
                <option value="rule_id">Rule ID</option>
                <option value="custom">Custom (detection_id + source)</option>
              </select>
            </div>
          </div>
          <div className="flex flex-wrap gap-4">
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="autoResolve"
                checked={settings.autoResolve}
                onChange={(e) => setSettings({ ...settings, autoResolve: e.target.checked })}
                className="rounded"
              />
              <label htmlFor="autoResolve" className="text-sm">
                Auto-resolve incidents when alerts are closed
              </label>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="includeDetails"
                checked={settings.includeAlertDetails}
                onChange={(e) => setSettings({ ...settings, includeAlertDetails: e.target.checked })}
                className="rounded"
              />
              <label htmlFor="includeDetails" className="text-sm">
                Include full alert details in incidents
              </label>
            </div>
          </div>
          <div className="flex justify-end">
            <button
              onClick={handleSaveSettings}
              disabled={isSaving}
              className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
            >
              {isSaving ? <RefreshCw size={14} className="animate-spin" /> : <Save size={14} />}
              Save Settings
            </button>
          </div>
        </div>
      </div>

      {/* Services */}
      <div className="bg-card rounded-lg border">
        <div className="flex items-center justify-between p-4 border-b">
          <div className="flex items-center gap-2">
            <Zap size={18} />
            <h2 className="font-semibold">Services</h2>
            <span className="text-xs bg-muted px-2 py-0.5 rounded">
              {services.length} configured
            </span>
          </div>
          <button
            onClick={() => setShowAddService(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90"
          >
            <Plus size={14} />
            Add Service
          </button>
        </div>

        {/* Add Service Form */}
        {showAddService && (
          <div className="p-4 border-b bg-muted/30">
            <h3 className="font-medium mb-4">Add PagerDuty Service</h3>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="block text-sm font-medium mb-1">Service Name</label>
                <input
                  type="text"
                  placeholder="Critical Security Alerts"
                  value={newService.name}
                  onChange={(e) => setNewService({ ...newService, name: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Integration Key</label>
                <input
                  type="text"
                  placeholder="Events API v2 integration key"
                  value={newService.integrationKey}
                  onChange={(e) => setNewService({ ...newService, integrationKey: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Escalation Policy</label>
                <input
                  type="text"
                  placeholder="Security On-Call"
                  value={newService.escalationPolicy}
                  onChange={(e) => setNewService({ ...newService, escalationPolicy: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Urgency</label>
                <select
                  value={newService.urgency}
                  onChange={(e) => setNewService({ ...newService, urgency: e.target.value as 'high' | 'low' | 'dynamic' })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                >
                  <option value="high">High (always page)</option>
                  <option value="low">Low (notification only)</option>
                  <option value="dynamic">Dynamic (based on severity)</option>
                </select>
              </div>
            </div>
            <div className="mt-4">
              <label className="block text-sm font-medium mb-2">Trigger for Severities</label>
              <div className="flex flex-wrap gap-2">
                {['critical', 'high', 'medium', 'low'].map((severity) => (
                  <button
                    key={severity}
                    onClick={() =>
                      setNewService({
                        ...newService,
                        severityMapping: newService.severityMapping.includes(severity)
                          ? newService.severityMapping.filter((s) => s !== severity)
                          : [...newService.severityMapping, severity],
                      })
                    }
                    className={cn(
                      'px-3 py-1.5 rounded text-sm capitalize',
                      newService.severityMapping.includes(severity)
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted'
                    )}
                  >
                    {severity}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-4">
              <button
                onClick={() => setShowAddService(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleAddService}
                disabled={isSaving || !newService.name || !newService.integrationKey}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                {isSaving ? <RefreshCw size={14} className="animate-spin" /> : <Save size={14} />}
                Add Service
              </button>
            </div>
          </div>
        )}

        {/* Service List */}
        <div className="divide-y">
          {services.map((service) => (
            <div key={service.id} className="p-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div
                  className={cn(
                    'w-10 h-10 rounded-lg flex items-center justify-center',
                    service.isEnabled ? 'bg-green-500/20' : 'bg-muted'
                  )}
                >
                  <Zap
                    size={18}
                    className={service.isEnabled ? 'text-green-400' : 'text-muted-foreground'}
                  />
                </div>
                <div>
                  <p className="font-medium">{service.name}</p>
                  <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Users size={10} />
                      {service.escalationPolicy}
                    </span>
                    <span>•</span>
                    <span className="flex items-center gap-1">
                      <Clock size={10} />
                      {service.urgency} urgency
                    </span>
                    <span>•</span>
                    <span>{service.severityMapping.join(', ')} alerts</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleTestService(service.id)}
                  disabled={testingService === service.id}
                  className="flex items-center gap-1 px-3 py-1.5 border rounded-md text-sm hover:bg-accent disabled:opacity-50"
                >
                  {testingService === service.id ? (
                    <>
                      <RefreshCw size={12} className="animate-spin" />
                      Testing...
                    </>
                  ) : (
                    <>
                      <Bell size={12} />
                      Test
                    </>
                  )}
                </button>
                <button
                  onClick={() => handleToggleService(service.id)}
                  className={cn(
                    'px-3 py-1.5 rounded-md text-sm',
                    service.isEnabled
                      ? 'bg-green-500/20 text-green-400'
                      : 'bg-muted text-muted-foreground'
                  )}
                >
                  {service.isEnabled ? 'Enabled' : 'Disabled'}
                </button>
                <button className="p-2 hover:bg-accent rounded-md">
                  <Edit size={14} />
                </button>
                <button className="p-2 hover:bg-accent rounded-md text-red-400">
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
