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
  Ticket,
  FolderOpen,
  Tag,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface JiraProject {
  id: string
  key: string
  name: string
  issueType: string
  defaultPriority: string
  autoCreate: boolean
  severityMapping: Record<string, string>
}

// Mock data
const mockProjects: JiraProject[] = [
  {
    id: '1',
    key: 'SEC',
    name: 'Security Operations',
    issueType: 'Security Incident',
    defaultPriority: 'High',
    autoCreate: true,
    severityMapping: {
      critical: 'Highest',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
    },
  },
  {
    id: '2',
    key: 'INC',
    name: 'Incident Response',
    issueType: 'Incident',
    defaultPriority: 'Medium',
    autoCreate: false,
    severityMapping: {
      critical: 'Highest',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
    },
  },
]

export default function JiraIntegrationPage() {
  const [isConnected, setIsConnected] = useState(true)
  const [projects, setProjects] = useState(mockProjects)
  const [showAddProject, setShowAddProject] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [isTesting, setIsTesting] = useState(false)

  const [settings, setSettings] = useState({
    instanceUrl: 'https://company.atlassian.net',
    email: 'security-bot@company.com',
    apiToken: '••••••••••••••••',
    syncInterval: '5',
    bidirectionalSync: true,
  })

  const [newProject, setNewProject] = useState({
    key: '',
    name: '',
    issueType: 'Task',
    defaultPriority: 'Medium',
    autoCreate: false,
  })

  const handleTestConnection = async () => {
    setIsTesting(true)
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setIsTesting(false)
  }

  const handleSaveSettings = async () => {
    setIsSaving(true)
    await new Promise((resolve) => setTimeout(resolve, 1000))
    setIsSaving(false)
  }

  const handleAddProject = async () => {
    if (!newProject.key || !newProject.name) return
    setIsSaving(true)
    await new Promise((resolve) => setTimeout(resolve, 1000))
    setProjects([
      ...projects,
      {
        id: Date.now().toString(),
        ...newProject,
        severityMapping: {
          critical: 'Highest',
          high: 'High',
          medium: 'Medium',
          low: 'Low',
        },
      },
    ])
    setNewProject({ key: '', name: '', issueType: 'Task', defaultPriority: 'Medium', autoCreate: false })
    setShowAddProject(false)
    setIsSaving(false)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link to="/integrations" className="p-2 hover:bg-accent rounded-md">
          <ArrowLeft size={20} />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <Ticket className="text-blue-500" />
            Jira Integration
          </h1>
          <p className="text-muted-foreground">
            Create and sync tickets with Jira projects
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
              <label className="block text-sm font-medium mb-1">Jira Instance URL</label>
              <input
                type="text"
                value={settings.instanceUrl}
                onChange={(e) => setSettings({ ...settings, instanceUrl: e.target.value })}
                placeholder="https://your-domain.atlassian.net"
                className="w-full px-3 py-2 bg-background border rounded-md"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Email</label>
              <input
                type="email"
                value={settings.email}
                onChange={(e) => setSettings({ ...settings, email: e.target.value })}
                placeholder="your-email@company.com"
                className="w-full px-3 py-2 bg-background border rounded-md"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">API Token</label>
              <input
                type="password"
                value={settings.apiToken}
                onChange={(e) => setSettings({ ...settings, apiToken: e.target.value })}
                placeholder="Your Jira API token"
                className="w-full px-3 py-2 bg-background border rounded-md"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Sync Interval (minutes)</label>
              <select
                value={settings.syncInterval}
                onChange={(e) => setSettings({ ...settings, syncInterval: e.target.value })}
                className="w-full px-3 py-2 bg-background border rounded-md"
              >
                <option value="1">1 minute</option>
                <option value="5">5 minutes</option>
                <option value="15">15 minutes</option>
                <option value="30">30 minutes</option>
                <option value="60">1 hour</option>
              </select>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="bidirectional"
              checked={settings.bidirectionalSync}
              onChange={(e) => setSettings({ ...settings, bidirectionalSync: e.target.checked })}
              className="rounded"
            />
            <label htmlFor="bidirectional" className="text-sm">
              Enable bidirectional sync (sync status changes from Jira back to alerts)
            </label>
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

      {/* Project Mappings */}
      <div className="bg-card rounded-lg border">
        <div className="flex items-center justify-between p-4 border-b">
          <div className="flex items-center gap-2">
            <FolderOpen size={18} />
            <h2 className="font-semibold">Project Mappings</h2>
            <span className="text-xs bg-muted px-2 py-0.5 rounded">
              {projects.length} projects
            </span>
          </div>
          <button
            onClick={() => setShowAddProject(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90"
          >
            <Plus size={14} />
            Add Project
          </button>
        </div>

        {/* Add Project Form */}
        {showAddProject && (
          <div className="p-4 border-b bg-muted/30">
            <h3 className="font-medium mb-4">Add Project Mapping</h3>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="block text-sm font-medium mb-1">Project Key</label>
                <input
                  type="text"
                  placeholder="SEC"
                  value={newProject.key}
                  onChange={(e) => setNewProject({ ...newProject, key: e.target.value.toUpperCase() })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Project Name</label>
                <input
                  type="text"
                  placeholder="Security Operations"
                  value={newProject.name}
                  onChange={(e) => setNewProject({ ...newProject, name: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Issue Type</label>
                <select
                  value={newProject.issueType}
                  onChange={(e) => setNewProject({ ...newProject, issueType: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                >
                  <option value="Task">Task</option>
                  <option value="Bug">Bug</option>
                  <option value="Story">Story</option>
                  <option value="Security Incident">Security Incident</option>
                  <option value="Incident">Incident</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Default Priority</label>
                <select
                  value={newProject.defaultPriority}
                  onChange={(e) => setNewProject({ ...newProject, defaultPriority: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                >
                  <option value="Highest">Highest</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                  <option value="Lowest">Lowest</option>
                </select>
              </div>
            </div>
            <div className="flex items-center gap-2 mt-4">
              <input
                type="checkbox"
                id="autoCreate"
                checked={newProject.autoCreate}
                onChange={(e) => setNewProject({ ...newProject, autoCreate: e.target.checked })}
                className="rounded"
              />
              <label htmlFor="autoCreate" className="text-sm">
                Auto-create tickets for new alerts
              </label>
            </div>
            <div className="flex justify-end gap-2 mt-4">
              <button
                onClick={() => setShowAddProject(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleAddProject}
                disabled={isSaving || !newProject.key || !newProject.name}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                {isSaving ? <RefreshCw size={14} className="animate-spin" /> : <Save size={14} />}
                Add Project
              </button>
            </div>
          </div>
        )}

        {/* Project List */}
        <div className="divide-y">
          {projects.map((project) => (
            <div key={project.id} className="p-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-lg bg-blue-500/20 flex items-center justify-center">
                  <span className="text-blue-400 font-bold">{project.key}</span>
                </div>
                <div>
                  <p className="font-medium">{project.name}</p>
                  <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Tag size={10} />
                      {project.issueType}
                    </span>
                    <span>•</span>
                    <span>Priority: {project.defaultPriority}</span>
                    {project.autoCreate && (
                      <>
                        <span>•</span>
                        <span className="text-green-400">Auto-create enabled</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
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

      {/* Severity Mapping */}
      <div className="bg-card rounded-lg border p-4">
        <h3 className="font-medium mb-4 flex items-center gap-2">
          <Tag size={16} />
          Default Severity Mapping
        </h3>
        <div className="grid gap-3 md:grid-cols-4">
          {['critical', 'high', 'medium', 'low'].map((severity) => (
            <div key={severity} className="flex items-center gap-2">
              <span className="text-sm capitalize w-20">{severity}:</span>
              <select className="flex-1 px-2 py-1 bg-background border rounded text-sm">
                <option>Highest</option>
                <option>High</option>
                <option>Medium</option>
                <option>Low</option>
                <option>Lowest</option>
              </select>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
